# kmod_guest/Makefile — snp_sync_kmod（guest 端内核模块）
#
# 必须针对 SNP guest kernel 编译，而非 host kernel。
# 用法：
#   make GUEST_KDIR=/lib/modules/<snp-guest-version>/build
#
# 从 src/Makefile 调用时传入 GUEST_KDIR。

obj-m := snp_sync_kmod.o

all:
	$(MAKE) -C $(GUEST_KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(GUEST_KDIR) M=$(PWD) clean 2>/dev/null || true
	rm -f *.o *.ko *.mod *.mod.c *.cmd modules.order Module.symvers
