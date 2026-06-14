// SPDX-License-Identifier: GPL-2.0
/*
 * snp_sync_kmod.c — AMD SEV-SNP 明文共享同步页 (guest 端内核模块)
 *
 * 功能：
 *   1. 分配一个物理页（GFP_KERNEL | __GFP_ZERO）。
 *   2. 调用 set_memory_decrypted()，将其从 C-bit=1（加密）改为 C-bit=0
 *      （明文共享），并在 RMP 表中标记为 Shared，允许 host 直接访问物理页。
 *   3. 注册 /dev/snp_sync 字符设备：
 *        ioctl SNP_SYNC_IOC_GET_GPA → 返回 GPA，供 guest_probe 打印到 debugcon
 *        mmap                       → 将共享页映射到 guest 用户态，供 guest_probe
 *                                     做原子计数器写
 *
 * host 端通过 GPA→HPA ioctl 找到物理页后，经 hpa_reader_kmod 的 mmap
 * 接口映射到用户态，直接 busy-poll 计数器。
 *
 * 时序（contention 模式）：
 *   guest: CLFLUSH(target) → DRAM-load(target) → atomic_inc(guest_seq)
 *   host:  while(*guest_seq == last) pause; → measure H1(same_page, NOCACHE)
 *
 * 同步延迟：cache coherence 协议（MOESI/MESIF），~100–500 ns（LLC 内），
 * 远优于文件轮询 ~50 µs，亦优于 ioeventfd ~1–5 µs。
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/page.h>
#include <asm/set_memory.h>

#include "snp_sync_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cohere");
MODULE_DESCRIPTION("SNP shared sync page — guest userspace ↔ host spinlock");

/* 全局状态：只支持单页，模块生命周期内固定 */
static struct page    *sync_page  = NULL;
static unsigned long   sync_virt  = 0;
static phys_addr_t     sync_phys  = 0;

/* ── ioctl ──────────────────────────────────────────────────────────────── */

static long snp_sync_ioctl(struct file *file, unsigned int cmd,
                            unsigned long arg)
{
    (void)file;

    if (cmd == SNP_SYNC_IOC_GET_GPA) {
        __u64 gpa = (__u64)sync_phys;
        if (copy_to_user((__u64 __user *)arg, &gpa, sizeof(gpa)))
            return -EFAULT;
        return 0;
    }
    if (cmd == SNP_SYNC_IOC_VA_TO_GPA) {
        struct snp_sync_va_to_gpa p;
        struct page *page = NULL;
        unsigned long uva;
        unsigned long off;
        long npinned;

        if (copy_from_user(&p, (void __user *)arg, sizeof(p)))
            return -EFAULT;

        uva = (unsigned long)p.va;
        off = uva & ~PAGE_MASK;
        uva &= PAGE_MASK;
        p.gpa = 0;
        p.ret = -EINVAL;

        if (!uva)
            goto out_copy;

        npinned = pin_user_pages_fast(uva, 1, 0, &page);
        if (npinned != 1) {
            p.ret = (npinned < 0) ? (int)npinned : -EFAULT;
            goto out_copy;
        }

        p.gpa = (__u64)page_to_phys(page) + (__u64)off;
        p.ret = 0;
        unpin_user_page(page);
out_copy:
        if (copy_to_user((void __user *)arg, &p, sizeof(p)))
            return -EFAULT;
        return 0;
    }
    return -ENOTTY;
}

/* ── mmap ───────────────────────────────────────────────────────────────── */

static int snp_sync_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long pfn;

    (void)file;
    if (size > PAGE_SIZE)
        return -EINVAL;

    pfn = sync_phys >> PAGE_SHIFT;

    /* C-bit=0：明文访问（与 set_memory_decrypted 操作一致） */
    vma->vm_page_prot = pgprot_decrypted(vma->vm_page_prot);
    /* Linux 6.3+ vm_flags 只读，需用 vm_flags_set() */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#else
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
#endif

    return remap_pfn_range(vma, vma->vm_start, pfn, size,
                           vma->vm_page_prot);
}

/* ── 设备注册 ────────────────────────────────────────────────────────────── */

static const struct file_operations snp_sync_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = snp_sync_ioctl,
    .mmap           = snp_sync_mmap,
};

static struct miscdevice snp_sync_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "snp_sync",
    .fops  = &snp_sync_fops,
    .mode  = 0600,
};

/* ── 模块初始化 ─────────────────────────────────────────────────────────── */

static int __init snp_sync_init(void)
{
    int ret;

    /* 分配一个物理连续页并清零 */
    sync_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!sync_page) {
        pr_err("snp_sync: alloc_page failed\n");
        return -ENOMEM;
    }
    sync_virt = (unsigned long)page_address(sync_page);
    sync_phys = page_to_phys(sync_page);

    /*
     * 将页标记为明文共享（C-bit=0）。
     * set_memory_decrypted() 会：
     *   1. 修改 guest 页表中的 C-bit；
     *   2. 执行 PVALIDATE（更新 RMP 表），允许 host 直接访问该物理页。
     * 非 SEV 系统上此函数为 NOP，模块仍可加载。
     */
    ret = set_memory_decrypted(sync_virt, 1);
    if (ret) {
        pr_err("snp_sync: set_memory_decrypted failed: %d\n", ret);
        __free_page(sync_page);
        sync_page = NULL;
        return ret;
    }

    ret = misc_register(&snp_sync_misc);
    if (ret) {
        pr_err("snp_sync: misc_register failed: %d\n", ret);
        set_memory_encrypted(sync_virt, 1);
        __free_page(sync_page);
        sync_page = NULL;
        return ret;
    }

    pr_info("snp_sync: shared sync page ready, gpa=0x%llx\n",
            (unsigned long long)sync_phys);
    return 0;
}

static void __exit snp_sync_exit(void)
{
    misc_deregister(&snp_sync_misc);
    if (sync_page) {
        /* 归还所有权给 guest（re-encrypt） */
        set_memory_encrypted(sync_virt, 1);
        __free_page(sync_page);
        sync_page = NULL;
    }
}

module_init(snp_sync_init);
module_exit(snp_sync_exit);
