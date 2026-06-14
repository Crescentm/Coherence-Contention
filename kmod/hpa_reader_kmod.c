#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/cacheflush.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
#include <asm/smp.h>

#include "hpa_reader_ioctl.h"

static DEFINE_MUTEX(hpa_reader_lock);
/* 用于 mmap 的共享（decrypted）物理页 HPA，由 HPA_READER_IOC_SET_SHARED_PAGE 设置 */
static u64 shared_page_hpa;

struct hpa_reader_file_ctx {
  void *mapped_page_base;
  u64 mapped_page_hpa;
  u32 mapped_page_mode;
};

static pgprot_t hpa_reader_mode_to_pgprot(u32 mode)
{
  if (mode == HPA_READER_MODE_HOSTDEC)
    return PAGE_KERNEL_NOCACHE;
  if (mode == HPA_READER_MODE_CIPHERTEXT)
    return pgprot_decrypted(PAGE_KERNEL_NOCACHE);
  if (mode == HPA_READER_MODE_HOSTDEC_CACHEABLE)
    return PAGE_KERNEL;
  if (mode == HPA_READER_MODE_CIPHERTEXT_CACHEABLE)
    return pgprot_decrypted(PAGE_KERNEL);
  return __pgprot(0);
}

static void hpa_reader_clear_mapping_locked(struct hpa_reader_file_ctx *ctx)
{
  if (!ctx)
    return;
  if (ctx->mapped_page_base) {
    vunmap(ctx->mapped_page_base);
    ctx->mapped_page_base = NULL;
  }
  ctx->mapped_page_hpa = 0;
  ctx->mapped_page_mode = 0;
}

static int hpa_reader_set_page_locked(struct hpa_reader_file_ctx *ctx,
                                      u64 page_hpa, u32 mode)
{
  struct page *page;
  void *base;
  unsigned long pfn;
  pgprot_t prot = hpa_reader_mode_to_pgprot(mode);

  if (!pgprot_val(prot))
    return -EINVAL;
  if (page_hpa & ~PAGE_MASK)
    return -EINVAL;

  if (ctx->mapped_page_base && ctx->mapped_page_hpa == page_hpa &&
      ctx->mapped_page_mode == mode)
    return 0;

  hpa_reader_clear_mapping_locked(ctx);

  pfn = page_hpa >> PAGE_SHIFT;
  page = pfn_to_page(pfn);
  if (!page)
    return -EINVAL;

  base = vmap(&page, 1, 0, prot);
  if (!base)
    return -ENOMEM;

  ctx->mapped_page_base = base;
  ctx->mapped_page_hpa = page_hpa;
  ctx->mapped_page_mode = mode;
  return 0;
}

static int hpa_reader_open(struct inode *inode, struct file *file)
{
  struct hpa_reader_file_ctx *ctx;

  (void)inode;
  ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
  if (!ctx)
    return -ENOMEM;
  file->private_data = ctx;
  return 0;
}

static int hpa_reader_release(struct inode *inode, struct file *file)
{
  struct hpa_reader_file_ctx *ctx = file->private_data;

  (void)inode;
  mutex_lock(&hpa_reader_lock);
  hpa_reader_clear_mapping_locked(ctx);
  mutex_unlock(&hpa_reader_lock);
  kfree(ctx);
  file->private_data = NULL;
  return 0;
}

static long hpa_reader_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  struct hpa_reader_file_ctx *ctx = file->private_data;
  struct hpa_reader_req req;
  struct hpa_reader_set_page_req set_req;
  struct hpa_reader_measure_req measure_req;
  struct hpa_reader_line_req line_req;
  struct page *page;
  void *base = NULL;
  unsigned long pfn;
  unsigned long offset;
  pgprot_t prot;
  long ret = 0;

  (void)file;

  if (cmd == HPA_READER_IOC_SET_PAGE) {
    if (copy_from_user(&set_req, (void __user *)arg, sizeof(set_req)))
      return -EFAULT;
    mutex_lock(&hpa_reader_lock);
    ret = hpa_reader_set_page_locked(ctx, set_req.page_hpa, set_req.mode);
    mutex_unlock(&hpa_reader_lock);
    return ret;
  }

  if (cmd == HPA_READER_IOC_MEASURE_LINE) {
    u8 value;
    u64 t0, t1;

    if (copy_from_user(&measure_req, (void __user *)arg, sizeof(measure_req)))
      return -EFAULT;
    if (measure_req.line >= 64)
      return -EINVAL;

    mutex_lock(&hpa_reader_lock);
    if (!ctx || !ctx->mapped_page_base) {
      ret = -ENXIO;
      goto out_measure;
    }
    t0 = rdtsc_ordered();
    value = READ_ONCE(*((volatile u8 *)ctx->mapped_page_base +
                        measure_req.line * 64U));
    barrier();
    t1 = rdtsc_ordered();
    measure_req.cycles = t1 - t0;
    measure_req.reserved = value;
out_measure:
    mutex_unlock(&hpa_reader_lock);
    if (ret)
      return ret;
    if (copy_to_user((void __user *)arg, &measure_req, sizeof(measure_req)))
      return -EFAULT;
    return 0;
  }

  if (cmd == HPA_READER_IOC_CLEAR_PAGE) {
    mutex_lock(&hpa_reader_lock);
    hpa_reader_clear_mapping_locked(ctx);
    mutex_unlock(&hpa_reader_lock);
    return 0;
  }

  if (cmd == HPA_READER_IOC_CLFLUSH_LINE) {
    if (copy_from_user(&line_req, (void __user *)arg, sizeof(line_req)))
      return -EFAULT;
    if (line_req.line >= 64)
      return -EINVAL;
    mutex_lock(&hpa_reader_lock);
    if (!ctx || !ctx->mapped_page_base) {
      ret = -ENXIO;
      goto out_clflush;
    }
    clflush_cache_range((u8 *)ctx->mapped_page_base + line_req.line * 64U, 64);
out_clflush:
    mutex_unlock(&hpa_reader_lock);
    return ret;
  }

  if (cmd == HPA_READER_IOC_SET_SHARED_PAGE) {
    u64 hpa;
    if (copy_from_user(&hpa, (void __user *)arg, sizeof(hpa)))
      return -EFAULT;
    if (hpa & ~PAGE_MASK)
      return -EINVAL;
    WRITE_ONCE(shared_page_hpa, hpa);
    return 0;
  }

  if (cmd != HPA_READER_IOC_READ)
    return -ENOTTY;

  if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
    return -EFAULT;

  if (req.size == 0 || req.size > HPA_READER_MAX_BYTES)
    return -EINVAL;

  offset = req.hpa & ~PAGE_MASK;
  if (offset + req.size > PAGE_SIZE)
    return -EINVAL;

  pfn = req.hpa >> PAGE_SHIFT;
  page = pfn_to_page(pfn);
  if (!page)
    return -EINVAL;

  prot = hpa_reader_mode_to_pgprot(req.mode);
  if (!pgprot_val(prot))
    return -EINVAL;

  wbinvd_on_all_cpus();
  base = vmap(&page, 1, 0, prot);
  if (!base)
    return -ENOMEM;

  memcpy(req.data, (u8 *)base + offset, req.size);
  vunmap(base);

  if (copy_to_user((void __user *)arg, &req, sizeof(req)))
    return -EFAULT;

  return 0;
}

/*
 * hpa_reader_mmap — 将 shared_page_hpa 映射到 host 用户态。
 *
 * 使用 pgprot_decrypted(vm_page_prot)：清除 host 侧页表的 C-bit，
 * 以 cacheable 方式访问 guest 共享（C-bit=0）物理页。
 * host 进程可直接 busy-poll uint64_t 计数器，延迟 ~100-500 ns。
 */
static int hpa_reader_mmap(struct file *file, struct vm_area_struct *vma)
{
  u64 hpa;
  unsigned long pfn;
  unsigned long size = vma->vm_end - vma->vm_start;

  (void)file;
  if (size > PAGE_SIZE)
    return -EINVAL;

  hpa = READ_ONCE(shared_page_hpa);
  if (!hpa)
    return -ENXIO;

  pfn = hpa >> PAGE_SHIFT;
  if (!pfn_valid(pfn))
    return -EINVAL;

  /* cacheable decrypted：C-bit=0，普通可缓存访问，利用 LLC coherence */
  vma->vm_page_prot = pgprot_decrypted(vma->vm_page_prot);
  /* Linux 6.3+ vm_flags 只读，需用 vm_flags_set() */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
  vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
#else
  vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
#endif

  return remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
}

static const struct file_operations hpa_reader_fops = {
  .owner = THIS_MODULE,
  .open = hpa_reader_open,
  .release = hpa_reader_release,
  .unlocked_ioctl = hpa_reader_ioctl,
  .mmap = hpa_reader_mmap,
#ifdef CONFIG_COMPAT
  .compat_ioctl = hpa_reader_ioctl,
#endif
};

static struct miscdevice hpa_reader_miscdev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "hpa_reader_cohere",
  .fops = &hpa_reader_fops,
  .mode = 0600,
};

static int __init hpa_reader_init(void)
{
  return misc_register(&hpa_reader_miscdev);
}

static void __exit hpa_reader_exit(void)
{
  misc_deregister(&hpa_reader_miscdev);
}

module_init(hpa_reader_init);
module_exit(hpa_reader_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cohere HPA reader for toggle experiments");
