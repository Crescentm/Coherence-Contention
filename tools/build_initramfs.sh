#!/bin/bash
# build_initramfs.sh — 构建最小 initramfs，包含 busybox + guest_probe
#
# 用法：
#   ./tools/build_initramfs.sh \
#     --guest-probe build/guest_probe \
#     --out build/initrd.img \
#     --kernel /boot/vmlinuz-6.16.0-snp-guest-...
#
# 输出：
#   --out 指定的 cpio.gz initrd 文件

set -euo pipefail

GUEST_PROBE=""
GUEST_CRYPTO_VALIDATE=""
GUEST_CRYPTO_SERVER=""
GUEST_VICTIM_AES=""
GUEST_VICTIM_RSA=""
GUEST_AES_NOASM_BENCH=""
GUEST_AES_ASM_BENCH=""
GUEST_AES_PERF=""
GUEST_RSA_BENCH=""
GUEST_AES_TOGGLE=""
OUT=""
KERNEL=""
GUEST_KMOD=""   # 可选：snp_sync_kmod.ko 路径
EXTRA_SRC=()    # 可选：额外源码目录（可重复）

while [[ $# -gt 0 ]]; do
    case "$1" in
        --guest-probe) GUEST_PROBE="$2"; shift 2 ;;
        --guest-crypto-validate) GUEST_CRYPTO_VALIDATE="$2"; shift 2 ;;
        --guest-crypto-server) GUEST_CRYPTO_SERVER="$2"; shift 2 ;;
        --guest-victim-aes) GUEST_VICTIM_AES="$2"; shift 2 ;;
        --guest-victim-rsa) GUEST_VICTIM_RSA="$2"; shift 2 ;;
        --guest-aes-noasm-bench) GUEST_AES_NOASM_BENCH="$2"; shift 2 ;;
        --guest-aes-asm-bench) GUEST_AES_ASM_BENCH="$2"; shift 2 ;;
        --guest-aes-perf) GUEST_AES_PERF="$2"; shift 2 ;;
        --guest-rsa-bench) GUEST_RSA_BENCH="$2"; shift 2 ;;
        --guest-aes-toggle) GUEST_AES_TOGGLE="$2"; shift 2 ;;
        --out)         OUT="$2";         shift 2 ;;
        --kernel)      KERNEL="$2";      shift 2 ;;
        --guest-kmod)  GUEST_KMOD="$2";  shift 2 ;;
        --extra-src)   EXTRA_SRC+=("$2"); shift 2 ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$GUEST_PROBE" || -z "$OUT" ]]; then
    echo "usage: $0 --guest-probe <bin> [--guest-crypto-validate <bin>] --out <initrd.img> [--kernel <vmlinuz>] [--guest-kmod <snp_sync_kmod.ko>] [--extra-src <dir>]..."
    exit 1
fi

WORKDIR=$(mktemp -d /tmp/initramfs_XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

# 目录结构
mkdir -p "$WORKDIR"/{bin,sbin,dev,proc,sys,tmp,mnt}

# busybox
BUSYBOX=$(which busybox-static 2>/dev/null || which busybox 2>/dev/null)
if [[ -z "$BUSYBOX" ]]; then
    echo "error: busybox-static not found" >&2
    exit 1
fi
cp "$BUSYBOX" "$WORKDIR/bin/busybox"
chmod +x "$WORKDIR/bin/busybox"

# busybox applets
for cmd in sh ls cat mkdir mount umount sleep echo printf ip ifconfig route; do
    ln -sf busybox "$WORKDIR/bin/$cmd"
done

# guest_probe
cp "$GUEST_PROBE" "$WORKDIR/bin/guest_probe"
chmod +x "$WORKDIR/bin/guest_probe"

# guest_crypto_validate（可选）：第 5.1 实验验证程序
if [[ -n "$GUEST_CRYPTO_VALIDATE" && -f "$GUEST_CRYPTO_VALIDATE" ]]; then
    cp "$GUEST_CRYPTO_VALIDATE" "$WORKDIR/bin/crypto_validate"
    chmod +x "$WORKDIR/bin/crypto_validate"
    echo "crypto_validate included from $GUEST_CRYPTO_VALIDATE"
fi

if [[ -n "$GUEST_CRYPTO_SERVER" && -f "$GUEST_CRYPTO_SERVER" ]]; then
    cp "$GUEST_CRYPTO_SERVER" "$WORKDIR/bin/crypto_server"
    chmod +x "$WORKDIR/bin/crypto_server"
    echo "crypto_server included from $GUEST_CRYPTO_SERVER"
fi

if [[ -n "$GUEST_VICTIM_AES" && -f "$GUEST_VICTIM_AES" ]]; then
    cp "$GUEST_VICTIM_AES" "$WORKDIR/bin/victim_aes"
    chmod +x "$WORKDIR/bin/victim_aes"
    echo "victim_aes included from $GUEST_VICTIM_AES"
fi

if [[ -n "$GUEST_VICTIM_RSA" && -f "$GUEST_VICTIM_RSA" ]]; then
    cp "$GUEST_VICTIM_RSA" "$WORKDIR/bin/victim_rsa"
    chmod +x "$WORKDIR/bin/victim_rsa"
    echo "victim_rsa included from $GUEST_VICTIM_RSA"
fi

if [[ -n "$GUEST_AES_NOASM_BENCH" && -f "$GUEST_AES_NOASM_BENCH" ]]; then
    cp "$GUEST_AES_NOASM_BENCH" "$WORKDIR/bin/aes_bench_noasm"
    chmod +x "$WORKDIR/bin/aes_bench_noasm"
    echo "aes_bench_noasm included from $GUEST_AES_NOASM_BENCH"
fi

if [[ -n "$GUEST_AES_ASM_BENCH" && -f "$GUEST_AES_ASM_BENCH" ]]; then
    cp "$GUEST_AES_ASM_BENCH" "$WORKDIR/bin/aes_bench_asm"
    chmod +x "$WORKDIR/bin/aes_bench_asm"
    echo "aes_bench_asm included from $GUEST_AES_ASM_BENCH"
fi

if [[ -n "$GUEST_AES_PERF" && -f "$GUEST_AES_PERF" ]]; then
    cp "$GUEST_AES_PERF" "$WORKDIR/bin/aes_perf"
    chmod +x "$WORKDIR/bin/aes_perf"
    echo "aes_perf included from $GUEST_AES_PERF"
fi

if [[ -n "$GUEST_RSA_BENCH" && -f "$GUEST_RSA_BENCH" ]]; then
    cp "$GUEST_RSA_BENCH" "$WORKDIR/bin/rsa_bench"
    chmod +x "$WORKDIR/bin/rsa_bench"
    echo "rsa_bench included from $GUEST_RSA_BENCH"
fi

if [[ -n "$GUEST_AES_TOGGLE" && -f "$GUEST_AES_TOGGLE" ]]; then
    cp "$GUEST_AES_TOGGLE" "$WORKDIR/bin/aes_toggle"
    chmod +x "$WORKDIR/bin/aes_toggle"
    echo "aes_toggle included from $GUEST_AES_TOGGLE"
fi

# snp_sync_kmod（可选）：若提供则打入 initramfs，init 启动时 insmod
if [[ -n "$GUEST_KMOD" && -f "$GUEST_KMOD" ]]; then
    cp "$GUEST_KMOD" "$WORKDIR/sbin/snp_sync_kmod.ko"
    echo "snp_sync_kmod.ko included from $GUEST_KMOD"
fi

# 额外源码（可选）：用于第 5 章实验在 guest 内直接访问参考实现源码
if [[ ${#EXTRA_SRC[@]} -gt 0 ]]; then
    mkdir -p "$WORKDIR/opt/crypto-src"
    for src in "${EXTRA_SRC[@]}"; do
        if [[ ! -d "$src" ]]; then
            echo "warning: extra source dir not found, skip: $src"
            continue
        fi
        name=$(basename "$src")
        dst="$WORKDIR/opt/crypto-src/$name"
        cp -a "$src" "$dst"
        rm -rf "$dst/.git"
        echo "extra source included: $src -> /opt/crypto-src/$name"
    done
fi

# /proc/self/pagemap 需要 /proc 挂载，console 需要 /dev
# /init 脚本
cat > "$WORKDIR/init" <<'INITEOF'
#!/bin/sh
# minimal init for SEV-SNP guest probe

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || true

# Bring up basic guest networking so hostfwd/tap can reach victim services.
if [ -x /bin/ip ]; then
    /bin/ip link set lo up 2>/dev/null || true
    /bin/ip link set eth0 up 2>/dev/null || true

    IPARG="$(cat /proc/cmdline | sed -n 's/.* ip=\([^ ]*\).*/\1/p')"
    if [ -n "$IPARG" ] && [ "$IPARG" != "dhcp" ]; then
        oldIFS="$IFS"
        IFS=':'
        set -- $IPARG
        IFS="$oldIFS"
        CLIENT_IP="$1"
        GATEWAY_IP="$3"
        addr_show="$(/bin/ip -4 addr show dev eth0 2>/dev/null || true)"
        case "$addr_show" in
            *"inet "*)
                ;;
            *)
                if [ -n "$CLIENT_IP" ]; then
                    /bin/ip addr add "$CLIENT_IP/24" dev eth0 2>/dev/null || true
                fi
                ;;
        esac
        if [ -n "$GATEWAY_IP" ]; then
            /bin/ip route add default via "$GATEWAY_IP" dev eth0 2>/dev/null || true
        fi
    fi
fi

# Try to allow perf events inside guest for root-driven benchmarks.
if [ -w /proc/sys/kernel/perf_event_paranoid ]; then
    echo -1 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true
fi


# 加载共享同步页模块（SEV-SNP 明文共享，供 host spinlock 同步）
if [ -f /sbin/snp_sync_kmod.ko ]; then
    echo "DEBUG: snp_sync_kmod.ko found, attempting to load..."
    insmod /sbin/snp_sync_kmod.ko && echo "snp_sync_kmod loaded successfully" \
        || echo "snp_sync_kmod load failed with exit code: $?"
else
    echo "ERROR: /sbin/snp_sync_kmod.ko not found"
fi

MODE="$(cat /proc/cmdline | sed -n 's/.*probe_mode=\([^ ]*\).*/\1/p')"
ORACLE_TE0="$(cat /proc/cmdline | sed -n 's/.*oracle_te0=\([^ ]*\).*/\1/p')"
ORACLE_TE0_OFF="$(cat /proc/cmdline | sed -n 's/.*oracle_te0_off=\([^ ]*\).*/\1/p')"
ORACLE_TE0_VMA="$(cat /proc/cmdline | sed -n 's/.*oracle_te0_vma=\([^ ]*\).*/\1/p')"
if [ "$MODE" = "crypto_validate" ] && [ -x /bin/crypto_validate ]; then
    /bin/crypto_validate
    rc=$?
    echo "crypto_validate exited with rc=$rc"
    # Keep PID1 alive; exiting init would trigger kernel panic.
    while true; do sleep 3600; done
fi

if [ "$MODE" = "crypto_server" ] && [ -x /bin/crypto_server ]; then
    /bin/crypto_server --port 5555 --reps 1
    rc=$?
    echo "crypto_server exited with rc=$rc"
    while true; do sleep 3600; done
fi

if [ "$MODE" = "victim_services" ] && [ -x /bin/victim_aes ] && [ -x /bin/victim_rsa ]; then
    AES_ARGS="--port 9000"
    AES_SYNC="$(sed -n 's/.*probe_victim_sync=\([^ ]*\).*/\1/p' /proc/cmdline)"
    AES_SYNC_PORT="$(sed -n 's/.*probe_victim_sync_port=\([^ ]*\).*/\1/p' /proc/cmdline)"
    AES_SYNC_GADGET="$(sed -n 's/.*probe_victim_sync_gadget=\([^ ]*\).*/\1/p' /proc/cmdline)"
    AES_SYNC_BYTE="$(sed -n 's/.*probe_victim_sync_byte=\([^ ]*\).*/\1/p' /proc/cmdline)"
    if [ "$ORACLE_TE0" = "1" ]; then
        AES_ARGS="$AES_ARGS --oracle-print-te0-gpa"
    fi
    if [ -n "$ORACLE_TE0_OFF" ]; then
        AES_ARGS="$AES_ARGS --oracle-te0-file-offset $ORACLE_TE0_OFF"
    fi
    if [ -n "$ORACLE_TE0_VMA" ]; then
        AES_ARGS="$AES_ARGS --oracle-te0-vma $ORACLE_TE0_VMA"
    fi
    if [ "$AES_SYNC" = "1" ]; then
        AES_ARGS="$AES_ARGS --sync-mailbox"
        if [ -n "$AES_SYNC_PORT" ]; then
            AES_ARGS="$AES_ARGS --sync-port $AES_SYNC_PORT"
        fi
        if [ "$AES_SYNC_GADGET" = "te0" ]; then
            AES_ARGS="$AES_ARGS --sync-gadget-te0"
        fi
        if [ -n "$AES_SYNC_BYTE" ]; then
            AES_ARGS="$AES_ARGS --sync-byte-pos $AES_SYNC_BYTE"
        fi
    fi
    # shellcheck disable=SC2086
    /bin/victim_aes $AES_ARGS &
    AES_PID=$!
    if [ "$ORACLE_TE0" = "1" ]; then
        # Let victim_aes print oracle line first; avoid mixed console output.
        sleep 1
    fi
    /bin/victim_rsa --port 9001 &
    RSA_PID=$!
    echo "victim services started: aes(pid=$AES_PID,port=9000), rsa(pid=$RSA_PID,port=9001)"
    while true; do sleep 3600; done
fi

if [ "$MODE" = "aes_toggle" ] && [ -x /bin/aes_toggle ]; then
    AES_TOGGLE_ARGS="$(cat /proc/cmdline | sed -n 's/.*probe_aes_toggle_args=\([^ ]*\).*/\1/p' | tr '_' ' ')"
    echo "[init] aes_toggle mode: /bin/aes_toggle $AES_TOGGLE_ARGS"
    # shellcheck disable=SC2086
    exec /bin/aes_toggle $AES_TOGGLE_ARGS
fi

if [ "$MODE" = "aes_perf" ] && [ -x /bin/aes_perf ]; then
    AES_PERF_ARGS="$(cat /proc/cmdline | sed -n 's/.*probe_aes_perf_args=\([^ ]*\).*/\1/p' | tr '_' ' ')"
    echo "[init] aes_perf mode: /bin/aes_perf $AES_PERF_ARGS"
    # shellcheck disable=SC2086
    /bin/aes_perf $AES_PERF_ARGS
    rc=$?
    echo "aes_perf exited with rc=$rc"
    while true; do sleep 3600; done
fi

exec /bin/guest_probe
INITEOF
chmod +x "$WORKDIR/init"

# 打包 cpio.gz
mkdir -p "$(dirname "$OUT")"
(cd "$WORKDIR" && find . | cpio --quiet -H newc -o) | gzip -9 > "$OUT"
echo "initramfs written to $OUT ($(du -sh "$OUT" | cut -f1))"

# 如果指定了 kernel，打印启动命令样例
if [[ -n "$KERNEL" ]]; then
    echo ""
    echo "Example QEMU kernel boot:"
    echo "  -kernel $KERNEL -initrd $OUT"
fi
