/* mode_aes_toggle.c — Host preload mode for AES toggle signal validation.
 *
 * Busy-polls guest_seq from the snp_sync mailbox. On each signal:
 *   1. Reads phase_kind (0=Group A, 1=Group B)
 *   2. Probes target_gpa with a configurable host probe mode
 *   3. Signals host_seq ack
 *   4. Records (seq, group, tsc_delta) to CSV
 *
 * Terminates when phase_done is set or reps exhausted.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"
void *hr_mode_aes_toggle_impl(void *arg) {
    const char *outdir = getenv("HR_OUTDIR");
    const char *sync_log = getenv("HR_SYNC_LOG");
    const char *env;
    int cpu = -1;
    int vm_fd = -1;
    int shared_fd = -1;
    uint64_t shared_gpa = 0;
    uint64_t last_cfg_seq = 0;
    uint64_t target_gpa = 0;
    uint64_t target_page_gpa = 0;
    uint64_t target_page_hpa = 0;
    uint32_t target_line = 0;
    uint64_t total_reps = 0;
    volatile uint64_t *shared_ptr = NULL;
    volatile struct sync_mailbox *mb = NULL;
    struct sync_cfg_snapshot cfg;
    uint64_t last_guest_seq = 0;
    FILE *csv = NULL, *summary = NULL, *done_f = NULL;
    char csv_path[512], summary_path[512], done_path[512];
    uint32_t reader_mode = HPA_READER_MODE_CIPHERTEXT_CACHEABLE;
    const char *probe_mode_name = "ciphertext_cacheable";
    const char *resolved_probe_mode_name = "ciphertext_cacheable";
    const char *tid_file = NULL;
    int burst_count = 1;
    int set_host_uc = 0;
    int probe_delay_us = 0;
    const char *score_mode = "mean";
    uint64_t n_a = 0, n_b = 0;
    uint64_t sum_a = 0, sum_b = 0;
    uint64_t min_a = ~0ULL, max_a = 0, min_b = ~0ULL, max_b = 0;

    (void)arg;
    if (!outdir || !sync_log)
        return NULL;
    tid_file = getenv("HR_TID_FILE");
    {
        long tid = syscall(SYS_gettid);
        pthread_setname_np(pthread_self(), "hr_aes_toggle");
        if (tid_file && *tid_file) {
            FILE *tf = fopen(tid_file, "w");
            if (tf) {
                fprintf(tf, "%ld\n", tid);
                fclose(tf);
            }
        }
    }
    if ((env = getenv("HR_CPU")))
        cpu = atoi(env);
    if ((env = getenv("HR_AES_TOGGLE_PROBE_MODE")) && *env) {
        if (strcmp(env, "nocache") == 0 || strcmp(env, "ciphertext") == 0) {
            reader_mode = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE;
            probe_mode_name = "ciphertext";
        } else if (strcmp(env, "cacheable") == 0 || strcmp(env, "ciphertext_cacheable") == 0) {
            reader_mode = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE;
            probe_mode_name = "ciphertext_cacheable";
        }
    }
    if ((env = getenv("HR_AES_TOGGLE_BURST")) && *env) {
        burst_count = atoi(env);
        if (burst_count < 1)
            burst_count = 1;
    }
    if ((env = getenv("HR_AES_TOGGLE_DELAY_US")) && *env) {
        probe_delay_us = atoi(env);
        if (probe_delay_us < 0)
            probe_delay_us = 0;
    }
    if ((env = getenv("HR_AES_TOGGLE_SET_HOST_UC")) && *env) {
        set_host_uc = atoi(env) ? 1 : 0;
    }
    if ((env = getenv("HR_AES_TOGGLE_SCORE_MODE")) && *env) {
        if (strcmp(env, "max") == 0)
            score_mode = "max";
        else
            score_mode = "mean";
    }

    wait_file_exists(sync_log);
    {
        uint64_t log_off = 0;
        if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0) {
            fprintf(stderr, "[HR/aes_toggle] wait_probe_shared_gpa failed\n");
            return NULL;
        }
    }

    maybe_pin_cpu(cpu);
    for (int i = 0; i < 50; i++) {
        vm_fd = find_self_kvm_vm_fd();
        if (vm_fd >= 0) break;
        usleep(100000);
    }
    if (vm_fd < 0) {
        fprintf(stderr, "[HR/aes_toggle] find_self_kvm_vm_fd failed\n");
        return NULL;
    }

    shared_ptr = map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, NULL);
    if (!shared_ptr) {
        fprintf(stderr, "[HR/aes_toggle] map_shared_counter_page failed\n");
        return NULL;
    }
    mb = (volatile struct sync_mailbox *)shared_ptr;

    if (wait_mailbox_magic(mb, 15.0) != 0) {
        fprintf(stderr, "[HR/aes_toggle] mailbox magic timeout\n");
        goto done;
    }
    if (wait_guest_cfg(mb, last_cfg_seq, 30.0, &cfg) != 0) {
        fprintf(stderr, "[HR/aes_toggle] wait_guest_cfg timeout\n");
        goto done;
    }
    last_cfg_seq = cfg.seq;
    if (cfg.mode != SYNC_CFG_MODE_TOGGLE) {
        fprintf(stderr, "[HR/aes_toggle] unexpected cfg_mode=%llu\n",
                (unsigned long long)cfg.mode);
        goto done;
    }
    target_gpa = cfg.target_gpa;
    target_page_gpa = target_gpa & ~(PAGE_SZ - 1ULL);
    target_line = (uint32_t)((target_gpa & (PAGE_SZ - 1ULL)) / LINE_SZ);
    total_reps = cfg.reps;  /* guest sends iters*2 total signals */

    if (translate_gpa_to_hpa(vm_fd, target_page_gpa, &target_page_hpa) != 0) {
        fprintf(stderr,
                "[HR/aes_toggle] translate_gpa_to_hpa failed: target_page_gpa=0x%llx\n",
                (unsigned long long)target_page_gpa);
        goto done;
    }
    if (set_host_uc) {
        struct kvm_memory_attributes attrs;
        memset(&attrs, 0, sizeof(attrs));
        attrs.address = target_page_gpa;
        attrs.size = PAGE_SZ;
        attrs.attributes = KVM_MEMORY_ATTRIBUTE_PRIVATE |
                           KVM_MEMORY_ATTRIBUTE_HOST_UC;
        if (ioctl(vm_fd, KVM_SET_MEMORY_ATTRIBUTES, &attrs) != 0) {
            fprintf(stderr,
                    "[HR/aes_toggle] ioctl(KVM_SET_MEMORY_ATTRIBUTES host_uc) failed: errno=%d (%s) page_gpa=0x%llx\n",
                    errno, strerror(errno), (unsigned long long)target_page_gpa);
            goto done;
        }
    }
    if (set_host_uc) {
        uint32_t resolved_mode = 0;
        (void)measure_line_ex_flags(vm_fd, target_page_gpa, (int)target_line,
                                    reader_mode,
                                    KVM_AMD_READ_GPA_F_WBINVD,
                                    &resolved_mode);
        if (resolved_mode == KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE)
            resolved_probe_mode_name = "ciphertext_forced_uc";
        else if (resolved_mode == KVM_AMD_READ_GPA_MODE_HOSTDEC_NOCACHE)
            resolved_probe_mode_name = "hostdec_forced_uc";
        else
            resolved_probe_mode_name = probe_mode_name;
    } else {
        resolved_probe_mode_name = probe_mode_name;
    }

    fprintf(stderr,
            "[HR/aes_toggle] target_gpa=0x%llx target_page_gpa=0x%llx target_page_hpa=0x%llx line=%u total_reps=%llu probe_mode=%s resolved_probe_mode=%s burst=%d delay_us=%d score_mode=%s host_uc=%d\n",
            (unsigned long long)target_gpa,
            (unsigned long long)target_page_gpa,
            (unsigned long long)target_page_hpa,
            target_line,
            (unsigned long long)total_reps,
            probe_mode_name,
            resolved_probe_mode_name,
            burst_count,
            probe_delay_us,
            score_mode,
            set_host_uc);

    if (ensure_dir_p(outdir) != 0)
        goto done;

    snprintf(csv_path,     sizeof(csv_path),     "%s/aes_toggle.csv",     outdir);
    snprintf(summary_path, sizeof(summary_path), "%s/aes_toggle_summary.txt", outdir);
    snprintf(done_path,    sizeof(done_path),     "%s/aes_toggle_done.txt", outdir);

    csv = fopen(csv_path, "w");
    if (!csv) goto done;
    fprintf(csv, "seq,group,tsc_delta,tsc_max,tsc_mean,burst_count,probe_mode,resolved_probe_mode,delay_us\n");

    last_guest_seq = __atomic_load_n((const uint64_t *)&mb->guest_seq, __ATOMIC_ACQUIRE);

    for (uint64_t rep = 0; rep < total_reps; rep++) {
        uint64_t seq = 0;
        uint64_t group, tsc;

        /* Check if guest signaled done early */
        if (__atomic_load_n((const uint64_t *)&mb->phase_done, __ATOMIC_ACQUIRE) != 0)
            break;

        if (wait_sync_guest_seq(mb, last_guest_seq, 10.0, &seq) != 0)
            break;

        /* Read group label (written by guest before incrementing guest_seq) */
        group = __atomic_load_n((const uint64_t *)&mb->phase_kind, __ATOMIC_ACQUIRE);

        /* Probe target cache line immediately (persistent page mapping path). */
        {
            uint64_t burst_sum = 0;
            uint64_t burst_max = 0;
            for (int bi = 0; bi < burst_count; bi++) {
                {
                    uint32_t resolved_mode = 0;
                    uint64_t flags = 0;
                    uint64_t cur = measure_line_ex_flags(vm_fd, target_page_gpa,
                                                         (int)target_line,
                                                         reader_mode, flags,
                                                         &resolved_mode);
                    if (!cur)
                        cur = 9999;
                    if (resolved_mode == KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE)
                        resolved_probe_mode_name = "ciphertext_forced_uc";
                    else if (resolved_mode == KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE)
                        resolved_probe_mode_name = "ciphertext_cacheable";
                    else if (resolved_mode == KVM_AMD_READ_GPA_MODE_HOSTDEC_NOCACHE)
                        resolved_probe_mode_name = "hostdec_forced_uc";
                    else if (resolved_mode == KVM_AMD_READ_GPA_MODE_HOSTDEC_CACHEABLE)
                        resolved_probe_mode_name = "hostdec_cacheable";
                    burst_sum += cur;
                    if (cur > burst_max)
                        burst_max = cur;
                }
                if (probe_delay_us > 0 && bi + 1 < burst_count)
                    usleep((useconds_t)probe_delay_us);
            }
            if (strcmp(score_mode, "max") == 0)
                tsc = burst_max;
            else
                tsc = burst_count > 0 ? (burst_sum / (uint64_t)burst_count) : burst_max;
            fprintf(csv, "%llu,%c,%llu,%llu,%.3f,%d,%s,%s,%d\n",
                    (unsigned long long)seq,
                    group == 0 ? 'A' : 'B',
                    (unsigned long long)tsc,
                    (unsigned long long)burst_max,
                    burst_count > 0 ? (double)burst_sum / (double)burst_count : 0.0,
                    burst_count,
                    probe_mode_name,
                    resolved_probe_mode_name,
                    probe_delay_us);
            if ((rep & 0xFF) == 0)
                fflush(csv);
        }

        /* Ack to guest */
        signal_sync_host_ack(mb, seq);
        last_guest_seq = seq;

        if (group == 0) {
            n_a++; sum_a += tsc;
            if (tsc < min_a) min_a = tsc;
            if (tsc > max_a) max_a = tsc;
        } else {
            n_b++; sum_b += tsc;
            if (tsc < min_b) min_b = tsc;
            if (tsc > max_b) max_b = tsc;
        }
    }
    fflush(csv);

    /* Write summary */
    summary = fopen(summary_path, "w");
    if (summary) {
        double mean_a = n_a ? (double)sum_a / n_a : 0.0;
        double mean_b = n_b ? (double)sum_b / n_b : 0.0;
        fprintf(summary,
                "target_gpa=0x%llx\n"
                "target_page_gpa=0x%llx\n"
                "target_page_hpa=0x%llx\n"
                "target_line=%u\n"
                "total_reps=%llu\n"
                "probe_mode=%s\n"
                "resolved_probe_mode=%s\n"
                "burst_count=%d\n"
                "probe_delay_us=%d\n"
                "score_mode=%s\n"
                "host_uc=%d\n"
                "n_a=%llu\n"
                "n_b=%llu\n"
                "mean_a=%.1f\n"
                "mean_b=%.1f\n"
                "min_a=%llu\n"
                "max_a=%llu\n"
                "min_b=%llu\n"
                "max_b=%llu\n"
                "separation=%.1f\n",
                (unsigned long long)target_gpa,
                (unsigned long long)target_page_gpa,
                (unsigned long long)target_page_hpa,
                target_line,
                (unsigned long long)total_reps,
                probe_mode_name,
                resolved_probe_mode_name,
                burst_count,
                probe_delay_us,
                score_mode,
                set_host_uc,
                (unsigned long long)n_a,
                (unsigned long long)n_b,
                mean_a, mean_b,
                (unsigned long long)(n_a ? min_a : 0),
                (unsigned long long)(n_a ? max_a : 0),
                (unsigned long long)(n_b ? min_b : 0),
                (unsigned long long)(n_b ? max_b : 0),
                mean_a - mean_b);
        fflush(summary);
    }

    done_f = fopen(done_path, "w");
    if (done_f) {
        fprintf(done_f, "probe_mode=%s resolved_probe_mode=%s burst=%d delay_us=%d score_mode=%s host_uc=%d n_a=%llu n_b=%llu mean_a=%.1f mean_b=%.1f sep=%.1f\n",
                probe_mode_name, resolved_probe_mode_name, burst_count, probe_delay_us, score_mode, set_host_uc,
                (unsigned long long)n_a, (unsigned long long)n_b,
                n_a ? (double)sum_a/n_a : 0.0,
                n_b ? (double)sum_b/n_b : 0.0,
                n_a && n_b ? (double)sum_a/n_a - (double)sum_b/n_b : 0.0);
        fflush(done_f);
    }

    fprintf(stderr, "[HR/aes_toggle] done: probe_mode=%s resolved_probe_mode=%s burst=%d delay_us=%d score_mode=%s host_uc=%d n_a=%llu n_b=%llu mean_a=%.1f mean_b=%.1f sep=%.1f\n",
            probe_mode_name, resolved_probe_mode_name, burst_count, probe_delay_us, score_mode, set_host_uc,
            (unsigned long long)n_a, (unsigned long long)n_b,
            n_a ? (double)sum_a/n_a : 0.0,
            n_b ? (double)sum_b/n_b : 0.0,
            n_a && n_b ? (double)sum_a/n_a - (double)sum_b/n_b : 0.0);

done:
    if (csv)     fclose(csv);
    if (summary) fclose(summary);
    if (done_f)  fclose(done_f);
    if (shared_ptr && shared_fd >= 0)
        munmap((void *)shared_ptr, PAGE_SZ);
    if (shared_fd >= 0)
        close(shared_fd);
    if (vm_fd >= 0)
        close(vm_fd);
    return NULL;
}

void *hr_main_thread_aes_toggle(void *arg) { return hr_mode_aes_toggle_impl(arg); }
