#ifndef HOST_RUNNER_PRELOAD_SHARED_H
#define HOST_RUNNER_PRELOAD_SHARED_H

#include <stdint.h>
#include <stddef.h>

#define PAGE_SZ 4096UL
#define LINE_SZ 64UL
#define LINES (PAGE_SZ / LINE_SZ)

/*
 * Shared sync mailbox layout on the mapped /dev/snp_sync page:
 *   guest_seq -> guest signals a new sample
 *   host_seq  -> host acknowledges that sample after probing
 *
 * guest_seq and host_seq are intentionally separated by a cache line so that
 * each side mostly writes its own line and only reads the other's line.
 */
struct sync_mailbox {
  volatile uint64_t guest_seq;
  uint8_t guest_pad[LINE_SZ - sizeof(uint64_t)];
  volatile uint64_t host_seq;
  uint8_t host_pad[LINE_SZ - sizeof(uint64_t)];
  volatile uint64_t phase_seq;
  uint8_t phase_pad[LINE_SZ - sizeof(uint64_t)];
  volatile uint64_t phase_ack;
  uint8_t phase_ack_pad[LINE_SZ - sizeof(uint64_t)];
  volatile uint64_t phase_kind;
  volatile uint64_t phase_vline;
  volatile uint64_t phase_target_gpa;
  volatile uint64_t phase_done;
  volatile uint64_t phase_magic;
  uint8_t phase_ctrl_pad[LINE_SZ - (5 * sizeof(uint64_t))];

  /* One-shot guest->host config handshake (all modes except blind):
   * guest fills cfg_* then increments cfg_ready_seq;
   * host reads cfg_* and stores cfg_ack_seq=cfg_ready_seq. */
  volatile uint64_t cfg_ready_seq;
  uint8_t cfg_ready_pad[LINE_SZ - sizeof(uint64_t)];
  volatile uint64_t cfg_ack_seq;
  uint8_t cfg_ack_pad[LINE_SZ - sizeof(uint64_t)];

  /* cfg line 0 (exactly one cache line) */
  volatile uint64_t cfg_mode;
  volatile uint64_t cfg_target_gpa;
  volatile uint64_t cfg_other_gpa;
  volatile uint64_t cfg_page_gpa;
  volatile uint64_t cfg_shared_gpa;
  volatile uint64_t cfg_dec_line;
  volatile uint64_t cfg_flags;
  volatile uint64_t cfg_reserved0;

  /* cfg line 1 */
  volatile uint64_t cfg_host_lines;
  volatile uint64_t cfg_reps;
  volatile uint64_t cfg_aux0;
  volatile uint64_t cfg_aux1;
  uint8_t cfg_aux_pad[LINE_SZ - (4 * sizeof(uint64_t))];
};

#define SYNC_PHASE_DONE UINT64_MAX
#define SYNC_MAILBOX_MAGIC 0x534e505f4d425831ULL /* "SNP_MBX1" */

#define SYNC_CFG_MODE_SYNC 1ULL
#define SYNC_CFG_MODE_SYNC_ALL 2ULL
#define SYNC_CFG_MODE_CONTENTION 3ULL
#define SYNC_CFG_MODE_PC 4ULL
#define SYNC_CFG_MODE_TOGGLE 5ULL
#define SYNC_CFG_MODE_CONTENTION_SPATIAL 6ULL

_Static_assert(offsetof(struct sync_mailbox, guest_seq) == 0, "guest_seq off");
_Static_assert(offsetof(struct sync_mailbox, host_seq) == LINE_SZ, "host_seq off");
_Static_assert(offsetof(struct sync_mailbox, phase_seq) == 2 * LINE_SZ, "phase_seq off");
_Static_assert(offsetof(struct sync_mailbox, phase_ack) == 3 * LINE_SZ, "phase_ack off");
_Static_assert(offsetof(struct sync_mailbox, phase_kind) == 4 * LINE_SZ, "phase_kind off");
_Static_assert(offsetof(struct sync_mailbox, phase_magic) == 4 * LINE_SZ + 4 * sizeof(uint64_t),
               "phase_magic off");
_Static_assert(offsetof(struct sync_mailbox, cfg_ready_seq) == 5 * LINE_SZ, "cfg_ready off");
_Static_assert(offsetof(struct sync_mailbox, cfg_ack_seq) == 6 * LINE_SZ, "cfg_ack off");
_Static_assert(offsetof(struct sync_mailbox, cfg_mode) == 7 * LINE_SZ, "cfg_mode off");
_Static_assert(offsetof(struct sync_mailbox, cfg_host_lines) == 8 * LINE_SZ, "cfg_aux off");
_Static_assert(sizeof(struct sync_mailbox) == 9 * LINE_SZ, "sync_mailbox size");

#ifdef HOST_RUNNER_PRELOAD

#include <linux/kvm.h>
#include "kmod/hpa_reader_ioctl.h"

#ifndef KVM_SET_MEMORY_ATTRIBUTES
#define KVM_SET_MEMORY_ATTRIBUTES              _IOW(KVMIO,  0xd2, struct kvm_memory_attributes)
struct kvm_memory_attributes {
	__u64 address;
	__u64 size;
	__u64 attributes;
	__u64 flags;
};
#endif

#ifndef KVM_MEMORY_ATTRIBUTE_PRIVATE
#define KVM_MEMORY_ATTRIBUTE_PRIVATE           (1ULL << 3)
#endif

#ifndef KVM_MEMORY_ATTRIBUTE_HOST_UC
#define KVM_MEMORY_ATTRIBUTE_HOST_UC           (1ULL << 4)
#endif

#define HPA_READER_DEV "/dev/hpa_reader_cohere"
#define KVM_AMD_GPA_TO_HPA _IOWR(KVMIO, 0xd6, struct kvm_amd_gpa_to_hpa)
#define KVM_AMD_READ_GPA _IOWR(KVMIO, 0xd7, struct kvm_amd_read_gpa)
#define KVM_AMD_NPT_CLEAR_ACCESSED _IOWR(KVMIO, 0xd8, struct kvm_amd_npt_clear_accessed)
#define KVM_AMD_NPT_SCAN_ACCESSED _IOWR(KVMIO, 0xd9, struct kvm_amd_npt_scan_accessed)
#define KVM_AMD_READ_GPA_BATCH _IOWR(KVMIO, 0xda, struct kvm_amd_read_gpa_batch)

#ifndef KVM_AMD_READ_GPA_MODE_HOSTDEC_NOCACHE
#define KVM_AMD_READ_GPA_MODE_HOSTDEC_NOCACHE 1
#endif
#define KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE 2
#ifndef KVM_AMD_READ_GPA_MODE_HOSTDEC_CACHEABLE
#define KVM_AMD_READ_GPA_MODE_HOSTDEC_CACHEABLE 3
#endif
#define KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE 4
#define KVM_AMD_NPT_ACCESS_F_FLUSH_TLB (1ULL << 0)
#define KVM_AMD_READ_GPA_F_WBINVD        (1ULL << 0)
#define KVM_AMD_READ_GPA_F_CLFLUSH_EACH  (1ULL << 1)
#define KVM_AMD_READ_GPA_BATCH_MAX_SAMPLES 65536U

struct kvm_amd_gpa_to_hpa {
  __u64 gpa;
  __u64 hpa;
  __u64 hva;
  __s32 ret;
  __u32 reserved;
};

struct kvm_amd_read_gpa {
  __u64 gpa;
  __u64 user_buf;
  __u32 size;
  __u32 mode;
  __u64 flags;
  __u64 resolved_hva;
  __u64 resolved_hpa;
  __u64 tsc_delta;
  __u64 aperf_delta;
  __s32 ret;
  __u32 reserved;
};

struct kvm_amd_read_gpa_batch {
  __u64 gpa;
  __u64 user_tsc_buf;
  __u64 user_aperf_buf;
  __u32 nr_samples;
  __u32 mode;
  __u64 flags;
  __u64 resolved_hva;
  __u64 resolved_hpa;
  __u64 tsc_sum;
  __u64 aperf_sum;
  __s32 ret;
  __u32 reserved;
};

struct kvm_amd_npt_clear_accessed {
  __u64 gpa_start;
  __u64 gpa_end;
  __u64 flags;
  __u32 pages_scanned;
  __u32 pages_cleared;
  __s32 ret;
  __u32 reserved;
};

struct kvm_amd_npt_scan_accessed {
  __u64 gpa_start;
  __u64 gpa_end;
  __u64 user_buf;
  __u32 max_entries;
  __u32 entries_written;
  __u32 pages_scanned;
  __u32 pages_accessed;
  __s32 ret;
  __u32 reserved;
};

struct shared_cursor {
  volatile uint64_t *ptr;
  uint64_t last_seen;
  uint64_t credit;
  uint64_t next_seq;
};

struct sync_cfg_snapshot {
  uint64_t seq;
  uint64_t mode;
  uint64_t target_gpa;
  uint64_t other_gpa;
  uint64_t page_gpa;
  uint64_t shared_gpa;
  uint64_t dec_line;
  uint64_t flags;
  uint64_t host_lines;
  uint64_t reps;
  uint64_t aux0;
  uint64_t aux1;
};

struct hr_reader_ctx {
  int fd;
  uint64_t page_gpa;
  uint64_t page_hpa;
  uint32_t mode;
  int is_bound;
};

void maybe_pin_cpu(int cpu);
void wait_file_exists(const char *path);
void shared_cursor_init(struct shared_cursor *c, volatile uint64_t *ptr);
int shared_consume(struct shared_cursor *c, double timeout_s,
                   uint64_t *seq_out);
int wait_sync_guest_seq(volatile struct sync_mailbox *mb, uint64_t last_seen,
                        double timeout_s, uint64_t *seq_out);
void signal_sync_host_ack(volatile struct sync_mailbox *mb, uint64_t seq);
int wait_phase_guest_seq(volatile struct sync_mailbox *mb, uint64_t last_seen,
                         double timeout_s, uint64_t *seq_out);
void signal_phase_host_ack(volatile struct sync_mailbox *mb, uint64_t seq);
int wait_mailbox_magic(volatile struct sync_mailbox *mb, double timeout_s);
int wait_guest_cfg(volatile struct sync_mailbox *mb, uint64_t last_seen,
                   double timeout_s, struct sync_cfg_snapshot *cfg_out);
int find_self_kvm_vm_fd(void);
int translate_gpa_to_hpa(int vm_fd, uint64_t gpa, uint64_t *hpa_out);
volatile uint64_t *map_shared_counter_page(int vm_fd, uint64_t shared_gpa,
                                           int *dev_fd_out,
                                           uint64_t *shared_hpa_out);
uint32_t hr_probe_mode_to_reader_mode(uint32_t probe_mode);
int hr_reader_open(struct hr_reader_ctx *ctx);
int hr_reader_bind(struct hr_reader_ctx *ctx, int vm_fd, uint64_t page_gpa,
                   uint32_t mode);
int hr_reader_measure_line(struct hr_reader_ctx *ctx, int line,
                           uint64_t *cycles_out);
int hr_reader_clflush_line(struct hr_reader_ctx *ctx, int line);
void hr_reader_close(struct hr_reader_ctx *ctx);
uint64_t measure_line_ex(int vm_fd, uint64_t page_gpa, int line, uint32_t mode);
uint64_t measure_line_ex_flags(int vm_fd, uint64_t page_gpa, int line,
                               uint32_t mode, uint64_t flags,
                               uint32_t *resolved_mode_out);
int ensure_dir_p(const char *path);
int wait_probe_shared_gpa(const char *sync_log, uint64_t *off,
                          uint64_t *shared_gpa);

void *hr_mode_single_impl(void *arg);
void *hr_mode_all_impl(void *arg);
void *hr_mode_contention_impl(void *arg);
void *hr_mode_toggle_impl(void *arg);
void *hr_mode_blind_impl(void *arg);
void *hr_mode_pc_impl(void *arg);
void *hr_mode_nptctl_impl(void *arg);
void *hr_mode_contention_spatial_impl(void *arg);

void *hr_main_thread_single(void *arg);
void *hr_main_thread_all(void *arg);
void *hr_main_thread_contention(void *arg);
void *hr_main_thread_contention_cacheable(void *arg);
void *hr_main_thread_contention_cmb(void *arg);
void *hr_main_thread_toggle(void *arg);
void *hr_main_thread_blind(void *arg);
void *hr_main_thread_pc(void *arg);
void *hr_main_thread_nptctl(void *arg);
void *hr_main_thread_aes_toggle(void *arg);
void *hr_main_thread_contention_spatial(void *arg);

#endif /* HOST_RUNNER_PRELOAD */

#endif
