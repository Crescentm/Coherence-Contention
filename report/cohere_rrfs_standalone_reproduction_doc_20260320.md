# Cohere / RRFS Standalone Reproduction Document

## 1. What You Are Trying to Reproduce

The target is the **RRFS-style heatmap** in an AMD SEV-SNP VM:

- a `64 x 64` matrix
- guest touches one cache line in a 4KB page
- host measures the latency of loading each cache line of either:
  - the **same page**
  - a **different page**
- the output should show:
  - a strong `2KB` partition structure on `same-page`
  - a flat low-latency matrix on `other-page`

This is the successful criterion.

## 2. The One Important High-Level Conclusion

To reproduce the RRFS heatmap successfully, the host observer must be:

1. a **ciphertext-side observer**
2. **cacheable**
3. backed by a KVM/SEV-Step-style `GPA -> HPA` translation
4. used for **single-load timing**

The most important practical lesson is:

**A `NOCACHE` ciphertext reader is good for snapshot/content experiments, but it is not the right observer for RRFS timing.**

## 3. Required Environment

### Hardware / firmware

- AMD EPYC Zen 3 class system
- SEV-SNP enabled

### Software stack

Use the **SEV-Step stack** as the known-good stack:

- SEV-Step host kernel
- SEV-Step QEMU
- SEV-Step OVMF

If you try to start from a stock kernel and an external module, you may spend a long time reproducing failures instead of the heatmap.

## 4. Minimal Architecture of the Successful Path

There are four moving parts:

### A. Guest workload

The guest does **one simple thing**:

- choose one victim line `Y` in a 4KB page
- repeatedly load from that line
- after each load, emit a synchronization event to the host

It also exposes:

- the GPA of the main page
- the GPA of a second page for the `other-page` control

### B. GPA to HPA translation

The host must be able to translate the page GPA to a page HPA using a **KVM-side** translation primitive.

The known-good primitive is:

- `KVM_SEV_STEP_GPA_TO_HPA`

This is important because the successful path did not come from a generic userspace/HVA approximation.

### C. HPA-backed ciphertext observer

Once the page HPA is known, the host maps that page in one of several modes.

The successful mode is:

- **ciphertext-side**
- **cacheable**

Conceptually:

- hostdec + cacheable = normal cacheable host view
- ciphertext + cacheable = cacheable opposite-domain observer
- hostdec + nocache = snapshot/plain observer
- ciphertext + nocache = snapshot/cipher observer

Only the **cacheable ciphertext** mode produced the RRFS heatmap.

### D. Timing loop

For each synchronization event from the guest:

- host loads one byte from `mapped_page_base + host_line * 64`
- measure cycles with `rdtsc`

The host repeats this for all `host_line = 0..63`, and for every `victim_line = 0..63`.

## 5. Exact Experiment Structure

You need two experiments:

### Experiment 1: same-page

- guest line `Y` and host line `X` are both inside the same 4KB page
- measure `64 x 64`

### Experiment 2: other-page

- guest line `Y` is in the main page
- host line `X` is in a second 4KB page
- measure `64 x 64`

The second experiment is the control.

## 6. Recommended Parameters

Use:

- `victim_lines = 0..63`
- `host_lines = 0..63`
- `reps = 8` for a first full run
- `reps = 32` or `128` for a smoother figure
- `mem = 4G`
- `smp = 1`
- guest vCPU pinned to one core
- host observer pinned to another core

Good core choices:

- guest/QEMU core: `32`
- host observer core: `33`

## 7. Guest Logic

The guest logic needed for the successful run is very small.

### Guest setup

Allocate two 4KB pages:

- `page_same`
- `page_other`

Choose a victim line:

- `victim_line = Y`

Compute:

- `target_addr = page_same + Y * 64`

Emit one startup header containing:

- `page_gpa`
- `other_page_gpa`
- the probe mode

### Guest loop

The loop is:

```text
while true:
    load(target_addr)
    emit_sync(seq)
    seq += 1
```

That is enough for the successful path.

The synchronization can be done through a debug port or another simple host-visible channel. The key is that the host receives one event per guest load.

## 8. Host Logic

The host logic has three nested layers:

### Layer 1: per victim line

For each `victim_line = 0..63`:

1. boot or configure the guest so it repeatedly touches that line
2. obtain:
   - main page GPA
   - other page GPA

### Layer 2: choose target page

For each of:

- `target_page = page_same`
- `target_page = page_other`

translate the page GPA to page HPA.

### Layer 3: sweep all host lines

For the translated page HPA:

1. create a fixed **cacheable ciphertext mapping**
2. for each `host_line = 0..63`:
   - wait for a guest sync event
   - time one load from `base + host_line * 64`
   - optionally also dump the 64B contents for debugging
   - repeat `reps` times
3. aggregate:
   - mean cycles
   - min cycles
   - max cycles
   - fraction above threshold

## 9. Pseudocode for the Successful Host Runner

```text
for victim_line in 0..63:
    configure guest to repeatedly load victim_line in page_same
    launch SNP VM

    read page_gpa and other_page_gpa from guest header

    for target in [page_gpa, other_page_gpa]:
        page_hpa = KVM_SEV_STEP_GPA_TO_HPA(target)

        map page_hpa as ciphertext + cacheable

        for host_line in 0..63:
            samples = []
            for rep in 0..reps-1:
                wait for next guest sync event
                t0 = rdtsc_ordered()
                load(base + host_line * 64)
                t1 = rdtsc_ordered()
                samples.append(t1 - t0)

            row[host_line] = aggregate(samples)

        save row for this victim_line

    terminate VM

assemble same_page matrix
assemble other_page matrix
render heatmaps
```

## 10. Pseudocode for the HPA Reader / Observer

The observer must expose two abilities:

1. set a fixed mapping for a page HPA
2. measure one host-line load on that mapping

### Supported mapping modes

You should conceptually support these four modes:

```text
HOSTDEC_NOCACHE
CIPHERTEXT_NOCACHE
HOSTDEC_CACHEABLE
CIPHERTEXT_CACHEABLE
```

### Correct mode for RRFS

Use only:

```text
CIPHERTEXT_CACHEABLE
```

### Set-page operation

```text
set_page(page_hpa, mode):
    if an old page is mapped:
        unmap it
    map the page with the pgprot corresponding to mode
    keep that mapping stable for later measurements
```

### Measure-line operation

```text
measure_line(line):
    addr = mapped_page_base + line * 64
    t0 = rdtsc_ordered()
    value = load(addr)
    t1 = rdtsc_ordered()
    return (t1 - t0), value
```

The important part is that:

- the mapping is already fixed
- the measurement is a direct single load

Do not rebuild the mapping inside the hot loop.

## 11. Timing Details

Use `TSC` as the primary timing source.

Recommended timed-load sequence:

```text
pin host observer to one CPU
disable preemption or otherwise minimize movement

lfence
t0 = rdtsc
load target byte
t1 = rdtsc
lfence
```

The measured load should be as close as possible to a single normal cached load.

## 12. What Not to Do

Do not switch the successful observer to `NOCACHE`.

Why:

- `NOCACHE` can still read content
- but it tends to produce uniformly high latency
- it hides the cache hit / miss structure needed for RRFS

Also avoid:

- remapping the page on every load
- expensive per-iteration kernel setup
- user-space helper chains in the hot measurement loop

## 13. Output Format

At minimum, generate:

- `same_page_matrix.csv`
- `other_page_matrix.csv`
- `same_page_heatmap_tsc.svg`
- `other_page_heatmap_tsc.svg`
- `summary.txt`

Each matrix cell should contain at least:

- mean cycles

Useful extra outputs:

- min cycles
- max cycles
- probability above threshold
- raw per-repetition samples
- raw read-back line contents

## 14. How to Decide Whether It Worked

Success means:

### same-page

- strong two-color or two-band partitioning
- high latency in the expected `2KB` partition
- low latency in the unexpected partition

### other-page

- mostly flat
- close to the low-latency baseline

### flip at line 32

This is the strongest visual check:

- for `victim_line < 32`, the slow region is `host_line < 32`
- for `victim_line >= 32`, the slow region is `host_line >= 32`

If that flip appears, the RRFS heatmap has been reproduced.

## 15. Recommended Execution Plan on a New Machine

### Phase 1: smoke

Run only:

- `victim_lines = 0..7`
- `reps = 8`

This verifies:

- SNP VM boots
- GPA->HPA translation works
- ciphertext cacheable observer works
- same-page begins to separate from other-page

### Phase 2: full matrix

Run:

- `victim_lines = 0..63`
- `reps = 8`

If the structure appears, the reproduction is already successful.

### Phase 3: smooth figure

If needed, rerun with:

- `reps = 32`
- or `reps = 128`

## 16. Minimal Success Checklist

Before stopping, verify all of the following:

- VM is SEV-SNP
- `Memory Interleaving=Disable`
- host observer is **ciphertext + cacheable**
- measurement uses direct single-load timing
- same-page shows a `2KB` partition
- other-page is flat
- partition flips around line `32`

If all of these are true, the Cohere / RRFS heatmap has been successfully reproduced.
