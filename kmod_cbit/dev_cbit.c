#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <asm/io.h>

static int cbit_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long pfn;
    size_t size = vma->vm_end - vma->vm_start;

    /* vma->vm_pgoff 就是应用层 mmap 传进来的 offset >> PAGE_SHIFT */
    pfn = vma->vm_pgoff;

    /* 必须设置 VM_IO，否则由于安全限制（STRICT_DEVMEM），内核拒绝隐式映射物理内存 */
    vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
    
    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
        printk(KERN_ERR "dev_cbit: remap_pfn_range failed for pfn %lx\n", pfn);
        return -EAGAIN;
    }

    return 0;
}

static const struct file_operations cbit_fops = {
    .owner = THIS_MODULE,
    .mmap = cbit_mmap,
};

static struct miscdevice cbit_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "cbit_mmap",
    .fops = &cbit_fops,
};

static int __init cbit_init(void)
{
    printk(KERN_INFO "dev_cbit: module loaded. Device /dev/cbit_mmap created.\n");
    return misc_register(&cbit_dev);
}

static void __exit cbit_exit(void)
{
    misc_deregister(&cbit_dev);
    printk(KERN_INFO "dev_cbit: module unloaded.\n");
}

module_init(cbit_init);
module_exit(cbit_exit);
MODULE_LICENSE("GPL");
