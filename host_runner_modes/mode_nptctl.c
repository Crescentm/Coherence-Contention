#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

#define NPTCTL_MAGIC 0x4E505443U /* "NPTC" */
#define NPTCTL_CMD_PING 1U
#define NPTCTL_CMD_GPA_TO_HPA 2U
#define NPTCTL_CMD_READ_GPA 3U
#define NPTCTL_CMD_NPT_CLEAR 4U
#define NPTCTL_CMD_NPT_SCAN 5U
#define NPTCTL_CMD_READ_GPA_BATCH 6U
#define NPTCTL_CMD_SYNC_MEASURE_MASK 7U
#define NPTCTL_SCAN_MAX_ENTRIES (1U << 20)

struct nptctl_req {
  uint32_t magic;
  uint16_t cmd;
  uint16_t reserved;
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
} __attribute__((packed));

struct nptctl_resp {
  uint32_t magic;
  uint16_t cmd;
  uint16_t status;   /* 0=ok, 1=error */
  int32_t sys_errno; /* errno when status=1 */
  int32_t kret;      /* ioctl inner ret (param.ret) */
  uint64_t v0;
  uint64_t v1;
  uint64_t v2;
  uint64_t v3;
} __attribute__((packed));

static int read_full(int fd, void *buf, size_t n) {
  uint8_t *p = (uint8_t *)buf;
  while (n > 0) {
    ssize_t r = read(fd, p, n);
    if (r == 0)
      return 0;
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += (size_t)r;
    n -= (size_t)r;
  }
  return 1;
}

static int write_full(int fd, const void *buf, size_t n) {
  const uint8_t *p = (const uint8_t *)buf;
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += (size_t)w;
    n -= (size_t)w;
  }
  return 0;
}

static void send_error_resp(int cfd, uint16_t cmd, int err_no, int kret) {
  struct nptctl_resp resp;
  memset(&resp, 0, sizeof(resp));
  resp.magic = NPTCTL_MAGIC;
  resp.cmd = cmd;
  resp.status = 1;
  resp.sys_errno = err_no;
  resp.kret = kret;
  (void)write_full(cfd, &resp, sizeof(resp));
}

struct nptctl_sync_state {
  const char *sync_log;
  uint64_t log_off;
  uint64_t shared_gpa;
  int shared_fd;
  volatile uint64_t *shared_ptr;
  volatile struct sync_mailbox *mb;
  uint64_t last_guest_seq;
  struct hr_reader_ctx reader;
  int ready;
  uint64_t dbg_sync_req_count;
};

static int nptctl_sync_debug_enabled(void) {
  const char *env = getenv("HR_SYNC_DEBUG");
  return env && atoi(env) != 0;
}

static void nptctl_sync_debugf(struct nptctl_sync_state *sync, const char *fmt, ...) {
  va_list ap;
  if (!nptctl_sync_debug_enabled())
    return;
  if (sync && sync->dbg_sync_req_count > 8)
    return;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

static void nptctl_sync_cleanup(struct nptctl_sync_state *sync) {
  if (!sync)
    return;
  hr_reader_close(&sync->reader);
  if (sync->shared_ptr && sync->shared_fd >= 0)
    munmap((void *)sync->shared_ptr, PAGE_SZ);
  if (sync->shared_fd >= 0)
    close(sync->shared_fd);
  sync->shared_fd = -1;
  sync->shared_ptr = NULL;
  sync->mb = NULL;
  sync->shared_gpa = 0;
  sync->last_guest_seq = 0;
  sync->ready = 0;
}

static double nptctl_sync_wait_timeout_s(void) {
  const char *env = getenv("HR_SYNC_WAIT_TIMEOUT_S");
  double timeout_s = 10.0;
  if (env && *env) {
    timeout_s = atof(env);
    if (timeout_s < 1.0)
      timeout_s = 1.0;
  }
  return timeout_s;
}

static int nptctl_sync_ensure_ready(int vm_fd, struct nptctl_sync_state *sync) {
  if (!sync || !sync->sync_log || !*sync->sync_log)
    return -1;
  if (sync->ready)
    return 0;
  nptctl_sync_debugf(sync, "[HR/nptctl-sync] ensure_ready: sync_log=%s\n",
                     sync->sync_log);

  wait_file_exists(sync->sync_log);
  if (wait_probe_shared_gpa(sync->sync_log, &sync->log_off, &sync->shared_gpa) !=
      0) {
    nptctl_sync_debugf(sync, "[HR/nptctl-sync] wait_probe_shared_gpa failed\n");
    return -1;
  }
  nptctl_sync_debugf(sync, "[HR/nptctl-sync] shared_gpa=0x%llx\n",
                     (unsigned long long)sync->shared_gpa);
  sync->shared_ptr =
      map_shared_counter_page(vm_fd, sync->shared_gpa, &sync->shared_fd, NULL);
  if (!sync->shared_ptr)
    return -1;
  sync->mb = (volatile struct sync_mailbox *)sync->shared_ptr;
  if (wait_mailbox_magic(sync->mb, 10.0) != 0) {
    nptctl_sync_cleanup(sync);
    return -1;
  }
  /* Track the last ACKed sequence, not the current guest_seq. Otherwise if the
   * first sync request arrives before ensure_ready() completes, we would miss
   * the pending seq and deadlock waiting for a non-existent next one. */
  sync->last_guest_seq =
      __atomic_load_n((const uint64_t *)&sync->mb->host_seq, __ATOMIC_ACQUIRE);
  if (hr_reader_open(&sync->reader) != 0) {
    nptctl_sync_cleanup(sync);
    return -1;
  }
  nptctl_sync_debugf(
      sync,
      "[HR/nptctl-sync] ready: host_seq=%llu guest_seq=%llu using_last_guest_seq=%llu\n",
      (unsigned long long)__atomic_load_n((const uint64_t *)&sync->mb->host_seq,
                                          __ATOMIC_ACQUIRE),
      (unsigned long long)__atomic_load_n((const uint64_t *)&sync->mb->guest_seq,
                                          __ATOMIC_ACQUIRE),
      (unsigned long long)sync->last_guest_seq);
  sync->ready = 1;
  return 0;
}

static int handle_one_req(int vm_fd, int cfd, struct nptctl_sync_state *sync) {
  struct nptctl_req req;
  struct nptctl_resp resp;
  int rr;

  rr = read_full(cfd, &req, sizeof(req));
  if (rr <= 0)
    return rr;

  if (req.magic != NPTCTL_MAGIC) {
    send_error_resp(cfd, req.cmd, EPROTO, -1);
    return 1;
  }

  memset(&resp, 0, sizeof(resp));
  resp.magic = NPTCTL_MAGIC;
  resp.cmd = req.cmd;

  if (req.cmd == NPTCTL_CMD_PING) {
    resp.status = 0;
    resp.kret = 0;
    resp.v0 = 1;
    return write_full(cfd, &resp, sizeof(resp)) == 0 ? 1 : -1;
  }

  if (req.cmd == NPTCTL_CMD_GPA_TO_HPA) {
    struct kvm_amd_gpa_to_hpa p;
    memset(&p, 0, sizeof(p));
    p.gpa = req.a;
    if (ioctl(vm_fd, KVM_AMD_GPA_TO_HPA, &p) != 0) {
      send_error_resp(cfd, req.cmd, errno, -1);
      return 1;
    }
    resp.status = 0;
    resp.kret = p.ret;
    resp.v0 = p.hpa;
    resp.v1 = p.hva;
    return write_full(cfd, &resp, sizeof(resp)) == 0 ? 1 : -1;
  }

  if (req.cmd == NPTCTL_CMD_READ_GPA) {
    static __attribute__((aligned(64))) uint8_t bounce[LINE_SZ];
    struct kvm_amd_read_gpa p;
    memset(&p, 0, sizeof(p));
    p.gpa = req.a;
    p.user_buf = (uint64_t)(uintptr_t)bounce;
    p.size = LINE_SZ;
    p.mode = (uint32_t)req.b;
    p.flags = 0;
    if (ioctl(vm_fd, KVM_AMD_READ_GPA, &p) != 0) {
      send_error_resp(cfd, req.cmd, errno, -1);
      return 1;
    }
    resp.status = 0;
    resp.kret = p.ret;
    resp.v0 = p.tsc_delta;
    resp.v1 = p.aperf_delta;
    resp.v2 = p.resolved_hpa;
    resp.v3 = p.resolved_hva;
    return write_full(cfd, &resp, sizeof(resp)) == 0 ? 1 : -1;
  }

  if (req.cmd == NPTCTL_CMD_READ_GPA_BATCH) {
    struct kvm_amd_read_gpa_batch p;
    uint64_t *tsc_buf = NULL;
    uint32_t nr = (uint32_t)req.c;

    if (nr == 0 || nr > KVM_AMD_READ_GPA_BATCH_MAX_SAMPLES) {
      send_error_resp(cfd, req.cmd, EINVAL, -1);
      return 1;
    }

    tsc_buf = (uint64_t *)calloc((size_t)nr, sizeof(uint64_t));
    if (!tsc_buf) {
      send_error_resp(cfd, req.cmd, ENOMEM, -1);
      return 1;
    }

    memset(&p, 0, sizeof(p));
    p.gpa = req.a;
    p.user_tsc_buf = (uint64_t)(uintptr_t)tsc_buf;
    p.user_aperf_buf = 0;
    p.nr_samples = nr;
    p.mode = (uint32_t)req.b;
    p.flags = req.d;

    if (ioctl(vm_fd, KVM_AMD_READ_GPA_BATCH, &p) != 0) {
      int err = errno;
      free(tsc_buf);
      send_error_resp(cfd, req.cmd, err, -1);
      return 1;
    }

    resp.status = 0;
    resp.kret = p.ret;
    resp.v0 = p.nr_samples;
    resp.v1 = p.resolved_hpa;
    resp.v2 = p.resolved_hva;
    resp.v3 = p.tsc_sum;
    if (write_full(cfd, &resp, sizeof(resp)) != 0) {
      free(tsc_buf);
      return -1;
    }
    if (write_full(cfd, tsc_buf, (size_t)p.nr_samples * sizeof(uint64_t)) != 0) {
      free(tsc_buf);
      return -1;
    }

    free(tsc_buf);
    return 1;
  }

  if (req.cmd == NPTCTL_CMD_SYNC_MEASURE_MASK) {
    uint64_t cycles[64];
    uint64_t seq = 0;
    int have_seq = 0;
    double sync_wait_timeout_s = nptctl_sync_wait_timeout_s();
    uint64_t line_mask = req.c;
    uint32_t mode = (uint32_t)req.b;
    uint32_t reader_mode = hr_probe_mode_to_reader_mode(mode);
    uint32_t repeats = (uint32_t)req.d;

    if (line_mask == 0 || reader_mode == UINT32_MAX) {
      send_error_resp(cfd, req.cmd, EINVAL, -1);
      return 1;
    }
    sync->dbg_sync_req_count++;
    nptctl_sync_debugf(sync,
                       "[HR/nptctl-sync] req#%llu page_gpa=0x%llx mode=%u mask=0x%llx repeats=%u\n",
                       (unsigned long long)sync->dbg_sync_req_count,
                       (unsigned long long)(req.a & ~(PAGE_SZ - 1ULL)),
                       reader_mode, (unsigned long long)line_mask, repeats);
    if (repeats == 0)
      repeats = 1;
    if (repeats > 32)
      repeats = 32;
    if (nptctl_sync_ensure_ready(vm_fd, sync) != 0) {
      send_error_resp(cfd, req.cmd, ENXIO, -1);
      return 1;
    }
    if (wait_sync_guest_seq(sync->mb, sync->last_guest_seq, sync_wait_timeout_s, &seq) != 0) {
      uint64_t guest_seq_now =
          __atomic_load_n((const uint64_t *)&sync->mb->guest_seq, __ATOMIC_ACQUIRE);
      uint64_t host_seq_now =
          __atomic_load_n((const uint64_t *)&sync->mb->host_seq, __ATOMIC_ACQUIRE);
      nptctl_sync_debugf(sync,
                         "[HR/nptctl-sync] wait_sync_guest_seq timeout: last_guest_seq=%llu guest_seq=%llu host_seq=%llu timeout_s=%.3f\n",
                         (unsigned long long)sync->last_guest_seq,
                         (unsigned long long)guest_seq_now,
                         (unsigned long long)host_seq_now,
                         sync_wait_timeout_s);
      if (guest_seq_now > sync->last_guest_seq) {
        signal_sync_host_ack(sync->mb, guest_seq_now);
        sync->last_guest_seq = guest_seq_now;
        nptctl_sync_debugf(sync,
                           "[HR/nptctl-sync] timeout recovery: best-effort ack guest_seq=%llu\n",
                           (unsigned long long)guest_seq_now);
      }
      send_error_resp(cfd, req.cmd, ETIMEDOUT, -1);
      return 1;
    }
    have_seq = 1;
    nptctl_sync_debugf(sync, "[HR/nptctl-sync] seq=%llu arrived\n",
                       (unsigned long long)seq);
    if (hr_reader_bind(&sync->reader, vm_fd, req.a & ~(PAGE_SZ - 1ULL),
                       reader_mode) != 0) {
      signal_sync_host_ack(sync->mb, seq);
      sync->last_guest_seq = seq;
      send_error_resp(cfd, req.cmd, errno ? errno : EIO, -1);
      return 1;
    }
    memset(cycles, 0, sizeof(cycles));
    for (uint32_t round = 0; round < repeats; round++) {
      for (int line = 0; line < 64; line++) {
        uint64_t t = 0;
        if ((line_mask & (1ULL << line)) == 0)
          continue;
        if (hr_reader_measure_line(&sync->reader, line, &t) != 0) {
          if (have_seq) {
            signal_sync_host_ack(sync->mb, seq);
            sync->last_guest_seq = seq;
          }
          send_error_resp(cfd, req.cmd, errno ? errno : EIO, -1);
          return 1;
        }
        if (t > cycles[line])
          cycles[line] = t;
      }
    }
    signal_sync_host_ack(sync->mb, seq);
    sync->last_guest_seq = seq;
    nptctl_sync_debugf(sync,
                       "[HR/nptctl-sync] seq=%llu acked page_hpa=0x%llx\n",
                       (unsigned long long)seq,
                       (unsigned long long)sync->reader.page_hpa);
    resp.status = 0;
    resp.kret = 0;
    resp.v0 = seq;
    resp.v1 = repeats;
    resp.v2 = sync->reader.page_hpa;
    resp.v3 = sync->shared_gpa;
    if (write_full(cfd, &resp, sizeof(resp)) != 0)
      return -1;
    if (write_full(cfd, cycles, sizeof(cycles)) != 0)
      return -1;
    return 1;
  }

  if (req.cmd == NPTCTL_CMD_NPT_CLEAR) {
    struct kvm_amd_npt_clear_accessed p;
    memset(&p, 0, sizeof(p));
    p.gpa_start = req.a;
    p.gpa_end = req.b;
    p.flags = req.c;
    if (ioctl(vm_fd, KVM_AMD_NPT_CLEAR_ACCESSED, &p) != 0) {
      send_error_resp(cfd, req.cmd, errno, -1);
      return 1;
    }
    resp.status = 0;
    resp.kret = p.ret;
    resp.v0 = p.pages_scanned;
    resp.v1 = p.pages_cleared;
    return write_full(cfd, &resp, sizeof(resp)) == 0 ? 1 : -1;
  }

  if (req.cmd == NPTCTL_CMD_NPT_SCAN) {
    struct kvm_amd_npt_scan_accessed p;
    uint64_t *pages = NULL;
    uint32_t max_entries = (uint32_t)req.c;
    if (max_entries > NPTCTL_SCAN_MAX_ENTRIES) {
      send_error_resp(cfd, req.cmd, E2BIG, -1);
      return 1;
    }
    if (max_entries > 0) {
      pages = (uint64_t *)calloc((size_t)max_entries, sizeof(uint64_t));
      if (!pages) {
        send_error_resp(cfd, req.cmd, ENOMEM, -1);
        return 1;
      }
    }
    memset(&p, 0, sizeof(p));
    p.gpa_start = req.a;
    p.gpa_end = req.b;
    p.user_buf = (uint64_t)(uintptr_t)pages;
    p.max_entries = max_entries;
    if (ioctl(vm_fd, KVM_AMD_NPT_SCAN_ACCESSED, &p) != 0) {
      int err = errno;
      free(pages);
      send_error_resp(cfd, req.cmd, err, -1);
      return 1;
    }
    resp.status = 0;
    resp.kret = p.ret;
    resp.v0 = p.entries_written;
    resp.v1 = p.pages_scanned;
    resp.v2 = p.pages_accessed;
    if (write_full(cfd, &resp, sizeof(resp)) != 0) {
      free(pages);
      return -1;
    }
    if (p.entries_written > 0 && pages) {
      size_t nbytes = (size_t)p.entries_written * sizeof(uint64_t);
      if (write_full(cfd, pages, nbytes) != 0) {
        free(pages);
        return -1;
      }
    }
    free(pages);
    return 1;
  }

  send_error_resp(cfd, req.cmd, EOPNOTSUPP, -1);
  return 1;
}

void *hr_mode_nptctl_impl(void *arg) {
  const char *sock_path = getenv("HR_NPT_SOCK");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *tid_file = getenv("HR_TID_FILE");
  const char *env;
  int cpu = -1;
  int vm_fd = -1;
  int lfd = -1;
  struct sockaddr_un addr;
  struct nptctl_sync_state sync;

  (void)arg;
  memset(&sync, 0, sizeof(sync));
  sync.shared_fd = -1;
  sync.reader.fd = -1;
  sync.sync_log = sync_log;
  {
    long tid = syscall(SYS_gettid);
    pthread_setname_np(pthread_self(), "hr_nptctl");
    if (tid_file && *tid_file) {
      FILE *tf = fopen(tid_file, "w");
      if (tf) {
        fprintf(tf, "%ld\n", tid);
        fclose(tf);
      }
    }
  }
  if (!sock_path || !*sock_path) {
    fprintf(stderr, "[HR/nptctl] missing HR_NPT_SOCK\n");
    return NULL;
  }
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);
  maybe_pin_cpu(cpu);

  for (int i = 0; i < 300; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }
  if (vm_fd < 0) {
    fprintf(stderr, "[HR/nptctl] find_self_kvm_vm_fd failed\n");
    return NULL;
  }

  lfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (lfd < 0) {
    fprintf(stderr, "[HR/nptctl] socket() failed: errno=%d\n", errno);
    return NULL;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(sock_path) >= sizeof(addr.sun_path)) {
    fprintf(stderr, "[HR/nptctl] socket path too long: %s\n", sock_path);
    close(lfd);
    return NULL;
  }
  strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
  unlink(sock_path);
  if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    fprintf(stderr, "[HR/nptctl] bind(%s) failed: errno=%d\n", sock_path, errno);
    close(lfd);
    return NULL;
  }
  if (listen(lfd, 4) != 0) {
    fprintf(stderr, "[HR/nptctl] listen() failed: errno=%d\n", errno);
    close(lfd);
    unlink(sock_path);
    return NULL;
  }
  fprintf(stderr, "[HR/nptctl] ready sock=%s vm_fd=%d\n", sock_path, vm_fd);

  while (1) {
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    while (1) {
      int hr = handle_one_req(vm_fd, cfd, &sync);
      if (hr <= 0)
        break;
    }
    close(cfd);
  }

  close(lfd);
  unlink(sock_path);
  nptctl_sync_cleanup(&sync);
  if (vm_fd >= 0)
    close(vm_fd);
  return NULL;
}

void *hr_main_thread_nptctl(void *arg) { return hr_mode_nptctl_impl(arg); }
