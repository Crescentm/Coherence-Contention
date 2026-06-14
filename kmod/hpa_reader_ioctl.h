#ifndef COHERE_HPA_READER_IOCTL_H
#define COHERE_HPA_READER_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define HPA_READER_MAX_BYTES 64

/* Keep mode values aligned with the old successful 5.19 reader path. */
enum hpa_reader_mode {
  HPA_READER_MODE_HOSTDEC = 0,
  HPA_READER_MODE_CIPHERTEXT = 1,
  HPA_READER_MODE_HOSTDEC_CACHEABLE = 2,
  HPA_READER_MODE_CIPHERTEXT_CACHEABLE = 3,
};

struct hpa_reader_req {
  __u64 hpa;
  __u32 size;
  __u32 mode;
  __u8 data[HPA_READER_MAX_BYTES];
};

struct hpa_reader_set_page_req {
  __u64 page_hpa;
  __u32 mode;
};

struct hpa_reader_measure_req {
  __u32 line;
  __u32 reserved;
  __u64 cycles;
};

struct hpa_reader_line_req {
  __u32 line;
  __u32 reserved;
};

#define HPA_READER_IOC_MAGIC 0xa7
#define HPA_READER_IOC_READ _IOWR(HPA_READER_IOC_MAGIC, 0x1, struct hpa_reader_req)
#define HPA_READER_IOC_SET_PAGE _IOW(HPA_READER_IOC_MAGIC, 0x2, struct hpa_reader_set_page_req)
#define HPA_READER_IOC_MEASURE_LINE _IOWR(HPA_READER_IOC_MAGIC, 0x3, struct hpa_reader_measure_req)
#define HPA_READER_IOC_CLEAR_PAGE _IO(HPA_READER_IOC_MAGIC, 0x4)
/* 设置用于 mmap 的共享物理页 HPA（guest shared/decrypted page），
 * 随后对 /dev/hpa_reader_cohere 调用 mmap() 即可将该页映射到用户态。
 * host 通过 busy-poll 该映射来接收 guest 的同步脉冲，延迟 ~100-500 ns。 */
#define HPA_READER_IOC_SET_SHARED_PAGE _IOW(HPA_READER_IOC_MAGIC, 0x5, __u64)
#define HPA_READER_IOC_CLFLUSH_LINE _IOW(HPA_READER_IOC_MAGIC, 0x6, struct hpa_reader_line_req)

#endif
