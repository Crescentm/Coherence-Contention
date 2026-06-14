#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import os
import subprocess
import time
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR.parent
REPO_ROOT = SRC_DIR.parent
RESULT_CH4 = REPO_ROOT / "result" / "ch4"
RUN_EXPERIMENT = SCRIPT_DIR / "run_experiment.py"

BUILD_DIR = SRC_DIR / "build"
PRELOAD_SO = BUILD_DIR / "libhost_runner.so"
INITRAMFS = BUILD_DIR / "initrd.img"
FR_VERIFY_BIN = BUILD_DIR / "fr_verify"

def _default_amdsev_dir() -> Path:
    p1 = Path("<COHERE_REPO>/AMDSEV")
    if p1.exists():
        return p1
    return Path("<AMDSEV_DIR>")


AMDSEV_DIR = Path(os.environ.get("AMDSEV_DIR", str(_default_amdsev_dir())))
QEMU_BIN = Path(
    os.environ.get(
        "QEMU_BIN", str(AMDSEV_DIR / "qemu" / "build" / "qemu-system-x86_64")
    )
)
OVMF_FD = Path(
    os.environ.get(
        "OVMF_FD",
        str(AMDSEV_DIR / "ovmf" / "Build" / "OvmfX64" / "DEBUG_GCC5" / "FV" / "OVMF.fd"),
    )
)

_kernel_env = os.environ.get("GUEST_KERNEL")
if _kernel_env:
    GUEST_KERNEL = Path(_kernel_env)
else:
    GUEST_KERNEL = next(iter(sorted(Path("/boot").glob("vmlinuz-*snp-guest*"))), Path(""))


def now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def dir_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def timestamped_outdir(exp_name: str, base: Path = RESULT_CH4) -> Path:
    return base / f"{exp_name}_{dir_stamp()}"


def print_banner(title: str, outdir: Path):
    print("=" * 50)
    print(f" {title}")
    print(f" outdir: {outdir}")
    print("=" * 50)


def run_checked(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout_path: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    print("[cmd]", " ".join(cmd))
    if stdout_path is None:
        return subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, env=env, check=check
        )
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("w") as fp:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=fp,
            stderr=subprocess.STDOUT,
            check=check,
        )


def ensure_artifacts(skip_build: bool, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    if skip_build:
        print("[build] skip_build=1")
        return
    log = outdir / "build.log"
    run_checked(["make", "all"], cwd=SRC_DIR, stdout_path=log)
    run_checked(["make", "initramfs"], cwd=SRC_DIR, stdout_path=log)
    print(f"[build] done: {log}")


def ensure_runtime_paths():
    missing: list[str] = []
    if not QEMU_BIN.exists():
        missing.append(f"QEMU not found: {QEMU_BIN}")
    if not OVMF_FD.exists():
        missing.append(f"OVMF not found: {OVMF_FD}")
    if not GUEST_KERNEL or not GUEST_KERNEL.exists():
        missing.append("SNP guest kernel not found; set GUEST_KERNEL")
    if not INITRAMFS.exists():
        missing.append(f"initramfs not found: {INITRAMFS}")
    if not PRELOAD_SO.exists():
        missing.append(f"preload library not found: {PRELOAD_SO}")
    if missing:
        raise SystemExit("[env] missing runtime paths:\n- " + "\n- ".join(missing))


def require_root(hint: str):
    if os.geteuid() != 0:
        raise SystemExit(hint)


def stop_proc(proc: subprocess.Popen, timeout_s: float = 5.0):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def run_qemu_background(
    cmd: list[str],
    *,
    log_path: Path,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fp = log_path.open("w")
    return subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=fp,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def wait_for_file(
    target: Path,
    *,
    proc: subprocess.Popen | None,
    timeout_s: int,
    poll_s: float = 1.0,
) -> bool:
    start = time.time()
    while time.time() - start < timeout_s:
        if target.exists():
            return True
        if proc is not None and proc.poll() is not None:
            return False
        time.sleep(poll_s)
    return target.exists()


def chown_to_sudo_user(path: Path):
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sudo_user == "root":
        return
    run_checked(["chown", "-R", f"{sudo_user}:{sudo_user}", str(path)], check=False)
