# Makefile — cohere/src
#
# 构建所有工件：
#   make all           — 构建 host_runner + guest_probe（静态 musl）
#   make guest_probe   — 只构建 guest workload（需要 musl-gcc）
#   make host_runner   — 只构建 host runner
#   make initramfs     — 构建 initrd.img（需要先 make guest_probe）
#   make clean
#
# 环境变量：
#   GUEST_KERNEL       — SNP guest vmlinuz 路径，默认自动查找
#   HOST_KVM_INCLUDE   — AMDSEV kvm.h uapi 头路径
#   INITRAMFS_OUT      — initramfs 输出路径，默认 build/initrd.img

CC      ?= cc
MUSL_CC ?= musl-gcc
CFLAGS  ?= -O2 -Wall -Wextra
KDIR    ?= /lib/modules/$(shell uname -r)/build

# host_runner 使用系统 /usr/include/linux/kvm.h；AMDSEV 专有 ioctl 直接在代码中定义
HOST_CFLAGS = $(CFLAGS)
GUEST_CFLAGS = -O2 -Wall -Wextra -static -march=x86-64 -mmmx -msse2 -maes

GUEST_KERNEL ?= $(shell ls /boot/vmlinuz-*snp-guest* 2>/dev/null | sort | tail -1)
GUEST_KVER   ?= $(shell echo "$(GUEST_KERNEL)" | sed 's|.*/vmlinuz-||')
GUEST_KDIR   ?= /lib/modules/$(GUEST_KVER)/build
INITRAMFS_OUT ?= build/initrd.img
CH5_CRYPTO_SRC_DIR ?= third_party/crypto
OPENSSL_340_SRC ?= $(CH5_CRYPTO_SRC_DIR)/openssl-3.4.0
LIBGCRYPT_176_SRC ?= $(CH5_CRYPTO_SRC_DIR)/libgcrypt-1.7.6
LIBGCRYPT_178_SRC ?= $(CH5_CRYPTO_SRC_DIR)/libgcrypt-1.7.8
OPENSSL_NOASM_BUILD ?= $(BUILD_DIR)/openssl_noasm
OPENSSL_ASM_BUILD ?= $(BUILD_DIR)/openssl_asm

INITRAMFS_EXTRA_SRC_ARGS = \
	$(if $(wildcard $(OPENSSL_340_SRC)),--extra-src $(OPENSSL_340_SRC),) \
	$(if $(wildcard $(LIBGCRYPT_176_SRC)),--extra-src $(LIBGCRYPT_176_SRC),) \
	$(if $(wildcard $(LIBGCRYPT_178_SRC)),--extra-src $(LIBGCRYPT_178_SRC),)

BUILD_DIR = build
KMOD_DIR = kmod
KMOD_NAME = hpa_reader_kmod
GUEST_KMOD_DIR  = kmod_guest
GUEST_KMOD_NAME = snp_sync_kmod

.PHONY: all guest_probe guest_crypto_validate guest_crypto_server guest_victim_aes guest_victim_rsa guest_aes_bench_noasm guest_aes_bench_asm guest_aes_perf guest_rsa_bench guest_aes_toggle host_runner host_runner_preload rrmb_probe_worker hpa_reader_kmod snp_sync_kmod fr_verify initramfs clean

all: guest_probe guest_crypto_validate guest_crypto_server guest_victim_aes guest_victim_rsa guest_aes_toggle guest_aes_perf host_runner host_runner_preload rrmb_probe_worker hpa_reader_kmod snp_sync_kmod fr_verify

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

guest_probe: $(BUILD_DIR)/guest_probe

$(BUILD_DIR)/guest_probe: guest_probe.c host_runner_preload_shared.h | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -o $@ $<

guest_crypto_validate: $(BUILD_DIR)/guest_crypto_validate

$(BUILD_DIR)/guest_crypto_validate: guest_crypto_validate.c | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -o $@ $< -lm

guest_crypto_server: $(BUILD_DIR)/guest_crypto_server

$(BUILD_DIR)/guest_crypto_server: guest_crypto_server.c $(OPENSSL_NOASM_BUILD)/libcrypto.a | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_NOASM_BUILD)/include -o $@ $< \
		$(OPENSSL_NOASM_BUILD)/libcrypto.a -ldl -pthread -lm

guest_victim_aes: $(BUILD_DIR)/guest_victim_aes

$(BUILD_DIR)/guest_victim_aes: guest_victim_aes.c $(OPENSSL_NOASM_BUILD)/libcrypto.a | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_NOASM_BUILD)/include -o $@ $< \
		$(OPENSSL_NOASM_BUILD)/libcrypto.a -ldl -pthread -lm

guest_victim_rsa: $(BUILD_DIR)/guest_victim_rsa

$(BUILD_DIR)/guest_victim_rsa: guest_victim_rsa.c $(OPENSSL_NOASM_BUILD)/libcrypto.a | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_NOASM_BUILD)/include -o $@ $< \
		$(OPENSSL_NOASM_BUILD)/libcrypto.a -ldl -pthread -lm

guest_aes_toggle: $(BUILD_DIR)/guest_aes_toggle

$(BUILD_DIR)/guest_aes_toggle: guest_aes_toggle.c $(OPENSSL_NOASM_BUILD)/libcrypto.a host_runner_preload_shared.h kmod_guest/snp_sync_ioctl.h | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_NOASM_BUILD)/include -o $@ $< \
		$(OPENSSL_NOASM_BUILD)/libcrypto.a -pthread -lm

$(OPENSSL_NOASM_BUILD)/libcrypto.a: tools/build_openssl_static.sh | $(BUILD_DIR)
	./tools/build_openssl_static.sh \
		--src $(OPENSSL_340_SRC) \
		--out $(OPENSSL_NOASM_BUILD) \
		--mode noasm \
		--cc "$(MUSL_CC)"

$(OPENSSL_ASM_BUILD)/libcrypto.a: tools/build_openssl_static.sh | $(BUILD_DIR)
	./tools/build_openssl_static.sh \
		--src $(OPENSSL_340_SRC) \
		--out $(OPENSSL_ASM_BUILD) \
		--mode asm \
		--cc "$(MUSL_CC)"

guest_aes_bench_noasm: $(BUILD_DIR)/guest_aes_bench_noasm

$(BUILD_DIR)/guest_aes_bench_noasm: guest_aes_bench.c $(OPENSSL_NOASM_BUILD)/libcrypto.a | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_NOASM_BUILD)/include -o $@ $< \
		$(OPENSSL_NOASM_BUILD)/libcrypto.a -ldl -pthread -lm

guest_aes_bench_asm: $(BUILD_DIR)/guest_aes_bench_asm

$(BUILD_DIR)/guest_aes_bench_asm: guest_aes_bench.c $(OPENSSL_ASM_BUILD)/libcrypto.a | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_ASM_BUILD)/include -o $@ $< \
		$(OPENSSL_ASM_BUILD)/libcrypto.a -ldl -pthread -lm

guest_aes_perf: $(BUILD_DIR)/guest_aes_perf

$(BUILD_DIR)/guest_aes_perf: guest_aes_perf.c $(OPENSSL_NOASM_BUILD)/libcrypto.a | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_NOASM_BUILD)/include -o $@ $< \
		$(OPENSSL_NOASM_BUILD)/libcrypto.a -ldl -pthread -lm

guest_rsa_bench: $(BUILD_DIR)/guest_rsa_bench

$(BUILD_DIR)/guest_rsa_bench: guest_rsa_bench.c $(OPENSSL_ASM_BUILD)/libcrypto.a | $(BUILD_DIR)
	$(MUSL_CC) $(GUEST_CFLAGS) -I$(OPENSSL_ASM_BUILD)/include -o $@ $< \
		$(OPENSSL_ASM_BUILD)/libcrypto.a -ldl -pthread -lm

host_runner: $(BUILD_DIR)/host_runner

$(BUILD_DIR)/host_runner: host_runner.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) -o $@ $<

host_runner_preload: $(BUILD_DIR)/libhost_runner.so

HOST_PRELOAD_SRCS = \
	host_runner_preload.c \
	host_runner_modes/common_runtime.c \
	host_runner_modes/mode_single.c \
	host_runner_modes/mode_all.c \
	host_runner_modes/mode_contention.c \
	host_runner_modes/mode_contention_cacheable.c \
	host_runner_modes/mode_contention_cmb.c \
	host_runner_modes/mode_contention_spatial.c \
	host_runner_modes/mode_toggle.c \
	host_runner_modes/mode_blind.c \
	host_runner_modes/mode_pc.c \
	host_runner_modes/mode_nptctl.c \
	host_runner_modes/mode_aes_toggle.c

$(BUILD_DIR)/libhost_runner.so: $(HOST_PRELOAD_SRCS) host_runner_preload_shared.h | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) -shared -fPIC -pthread -o $@ $(HOST_PRELOAD_SRCS)

rrmb_probe_worker: $(BUILD_DIR)/rrmb_probe_worker

$(BUILD_DIR)/rrmb_probe_worker: tools/rrmb_probe_worker.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) -o $@ $<

fr_verify: $(BUILD_DIR)/fr_verify

$(BUILD_DIR)/fr_verify: tools/fr_verify.c | $(BUILD_DIR)
	$(CC) -O2 -Wall -o $@ $<

hpa_reader_kmod: $(BUILD_DIR)/$(KMOD_NAME).ko

$(BUILD_DIR)/$(KMOD_NAME).ko: $(KMOD_DIR)/Makefile $(KMOD_DIR)/hpa_reader_kmod.c $(KMOD_DIR)/hpa_reader_ioctl.h | $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(abspath $(KMOD_DIR)) modules
	cp $(KMOD_DIR)/$(KMOD_NAME).ko $@

snp_sync_kmod: $(BUILD_DIR)/$(GUEST_KMOD_NAME).ko

$(BUILD_DIR)/$(GUEST_KMOD_NAME).ko: $(GUEST_KMOD_DIR)/Makefile $(GUEST_KMOD_DIR)/snp_sync_kmod.c $(GUEST_KMOD_DIR)/snp_sync_ioctl.h | $(BUILD_DIR)
	@if [ -z "$(GUEST_KVER)" ]; then \
		echo "ERROR: No SNP guest kernel found. Set GUEST_KDIR explicitly:"; \
		echo "  make snp_sync_kmod GUEST_KDIR=/lib/modules/<kver>/build"; \
		exit 1; \
	fi
	$(MAKE) -C $(GUEST_KDIR) M=$(abspath $(GUEST_KMOD_DIR)) modules
	cp $(GUEST_KMOD_DIR)/$(GUEST_KMOD_NAME).ko $@

initramfs: $(BUILD_DIR)/guest_probe $(BUILD_DIR)/guest_crypto_validate $(BUILD_DIR)/guest_crypto_server $(BUILD_DIR)/guest_victim_aes $(BUILD_DIR)/guest_victim_rsa $(BUILD_DIR)/guest_aes_bench_noasm $(BUILD_DIR)/guest_aes_bench_asm $(BUILD_DIR)/guest_aes_perf $(BUILD_DIR)/guest_rsa_bench $(BUILD_DIR)/guest_aes_toggle $(BUILD_DIR)/$(GUEST_KMOD_NAME).ko | $(BUILD_DIR)
	./tools/build_initramfs.sh \
		--guest-probe $(BUILD_DIR)/guest_probe \
		--guest-crypto-validate $(BUILD_DIR)/guest_crypto_validate \
		--guest-crypto-server $(BUILD_DIR)/guest_crypto_server \
		--guest-victim-aes $(BUILD_DIR)/guest_victim_aes \
		--guest-victim-rsa $(BUILD_DIR)/guest_victim_rsa \
		--guest-aes-noasm-bench $(BUILD_DIR)/guest_aes_bench_noasm \
		--guest-aes-asm-bench $(BUILD_DIR)/guest_aes_bench_asm \
		--guest-aes-perf $(BUILD_DIR)/guest_aes_perf \
		--guest-rsa-bench $(BUILD_DIR)/guest_rsa_bench \
		--guest-aes-toggle $(BUILD_DIR)/guest_aes_toggle \
		--guest-kmod  $(BUILD_DIR)/$(GUEST_KMOD_NAME).ko \
		$(INITRAMFS_EXTRA_SRC_ARGS) \
		--out $(INITRAMFS_OUT) \
		--kernel "$(GUEST_KERNEL)"

clean:
	-$(MAKE) -C $(KDIR) M=$(abspath $(KMOD_DIR)) clean
	-$(MAKE) -C $(GUEST_KDIR) M=$(abspath $(GUEST_KMOD_DIR)) clean 2>/dev/null || true
	rm -rf $(BUILD_DIR)
