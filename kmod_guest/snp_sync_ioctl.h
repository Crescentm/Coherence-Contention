/* snp_sync_ioctl.h — 共享同步页 ioctl 定义
 *
 * 兼容 kernel 和 userspace（musl/glibc）。
 *
 * 依赖：
 *   kernel  : #include "snp_sync_ioctl.h"（在 linux/ioctl.h 之后）
 *   userspace: #include <sys/ioctl.h>，再 #include "snp_sync_ioctl.h"
 */
#ifndef SNP_SYNC_IOCTL_H
#define SNP_SYNC_IOCTL_H

#ifdef __KERNEL__
#  include <linux/ioctl.h>
#  include <linux/types.h>
#  define _SNP_U64 __u64
#  define _SNP_S32 __s32
#  define _SNP_U32 __u32
#else
#  include <sys/ioctl.h>
#  include <stdint.h>
#  define _SNP_U64 uint64_t
#  define _SNP_S32 int32_t
#  define _SNP_U32 uint32_t
#endif

#define SNP_SYNC_DEV  "/dev/snp_sync"

/* ioctl 幻数 — 避免与 hpa_reader(0xa7) 冲突 */
#define SNP_SYNC_IOC_MAGIC  0xB3u

/* 获取共享同步页的 GPA（如 0x1234000），host 再由此查 HPA */
#define SNP_SYNC_IOC_GET_GPA  _IOR(SNP_SYNC_IOC_MAGIC, 0x01, _SNP_U64)

/* 查询任意用户态 VA 对应 GPA（用于实验真值校验，不依赖 procfs 映射接口） */
struct snp_sync_va_to_gpa {
	_SNP_U64 va;
	_SNP_U64 gpa;
	_SNP_S32 ret;
	_SNP_U32 reserved;
};
#define SNP_SYNC_IOC_VA_TO_GPA _IOWR(SNP_SYNC_IOC_MAGIC, 0x02, struct snp_sync_va_to_gpa)

/* 共享页内存布局（4096 字节）：
 *   offset  0 : uint64_t guest_seq  — guest 每次 DRAM 加载后 +1（原子写）
 *   offset  8 : uint64_t host_seq   — host 可选反馈（未使用）
 *   offset 16 : 保留
 *
 * host busy-poll：while (*guest_seq == last) { pause; }
 */
#define SNP_SYNC_OFF_GUEST_SEQ  0u
#define SNP_SYNC_OFF_HOST_SEQ   8u

#endif /* SNP_SYNC_IOCTL_H */
