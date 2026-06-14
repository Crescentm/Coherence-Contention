import csv
import numpy as np
import matplotlib.pyplot as plt

plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans'] # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False # 用来正常显示负号

from scipy import stats
import os

# Configuration
EXP_DIR = "<COHERE_REPO>/result/ch4/exp4_1_b"
H0_FILE = os.path.join(EXP_DIR, "raw_h0_cycles.csv")
H1_FILE = os.path.join(EXP_DIR, "raw_h1_cycles.csv")
OUT_IMG = os.path.join(EXP_DIR, "delay_histogram.png")
OUT_TXT = os.path.join(EXP_DIR, "stats_41b.txt")

def load_csv(filepath):
    data = []
    with open(filepath, 'r') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if not row: continue
            try:
                val = float(row[0])
                data.append(val)
            except ValueError:
                pass
    return np.array(data)

def filter_outliers(data, threshold=2000):
    return data[data <= threshold]

def main():
    if not os.path.exists(H0_FILE) or not os.path.exists(H1_FILE):
        print(f"Error: Missing CSV files in {EXP_DIR}")
        return

    # Load data
    h0_cycles = load_csv(H0_FILE)
    h1_cycles = load_csv(H1_FILE)
    
    # Filter out bizarrely high values (e.g., interrupts)
    h0_cycles = filter_outliers(h0_cycles)
    h1_cycles = filter_outliers(h1_cycles)

    # Calculate Statistics
    h0_mean, h0_median, h0_std = np.mean(h0_cycles), np.median(h0_cycles), np.std(h0_cycles)
    h1_mean, h1_median, h1_std = np.mean(h1_cycles), np.median(h1_cycles), np.std(h1_cycles)
    
    delta_coh_median = h1_median - h0_median
    delta_coh_mean = h1_mean - h0_mean

    # Output Statistics
    with open(OUT_TXT, "w") as f:
        f.write("=== Experiment 4.1-B: Cross-Domain Eviction Delay Measurement ===\n\n")
        f.write("[H0] Baseline (Other Page / No Eviction):\n")
        f.write(f"  Count:  {len(h0_cycles)}\n")
        f.write(f"  Mean:   {h0_mean:.2f} cycles\n")
        f.write(f"  Median: {h0_median:.0f} cycles\n")
        f.write(f"  StdDev: {h0_std:.2f} cycles\n\n")
        
        f.write("[H1] Eviction (Same Page / Forced Eviction):\n")
        f.write(f"  Count:  {len(h1_cycles)}\n")
        f.write(f"  Mean:   {h1_mean:.2f} cycles\n")
        f.write(f"  Median: {h1_median:.0f} cycles\n")
        f.write(f"  StdDev: {h1_std:.2f} cycles\n\n")
        
        f.write("[Results]\n")
        f.write(f"  Delta_coh (Median diff): {delta_coh_median:.0f} cycles\n")
        f.write(f"  Delta_coh (Mean diff):   {delta_coh_mean:.2f} cycles\n")

    print(f"Statistics written to {OUT_TXT}")

    # Plot Histogram + KDE
    plt.figure(figsize=(10, 6))
    
    # Define bins
    min_val = min(np.min(h0_cycles), np.min(h1_cycles))
    max_val = max(np.max(h0_cycles), np.max(h1_cycles))
    # Clip max_val for better visualization if there's a long tail
    display_max = min(max_val, 1500)
    bins = np.linspace(min_val, display_max, 100)

    # Plot Hit (H0) vs Miss/Eviction (H1) using density=True
    plt.hist(h0_cycles, bins=bins, color='blue', alpha=0.5, density=True, label=f'H0 (Baseline), Median={h0_median:.0f}')
    plt.hist(h1_cycles, bins=bins, color='red', alpha=0.5, density=True, label=f'H1 (Eviction), Median={h1_median:.0f}')

    # Try plotting KDE
    try:
        kde_h0 = stats.gaussian_kde(h0_cycles)
        kde_h1 = stats.gaussian_kde(h1_cycles)
        x_eval = np.linspace(min_val, display_max, 500)
        plt.plot(x_eval, kde_h0(x_eval), color='darkblue', lw=2)
        plt.plot(x_eval, kde_h1(x_eval), color='darkred', lw=2)
    except Exception as e:
        print(f"Could not render KDE (probably standard deviation is 0 or array too small): {e}")

    plt.title('Cross-Domain Eviction Delay Distribution (H0 vs H1)', fontsize=14)
    plt.xlabel('Latency (CPU Cycles)', fontsize=12)
    plt.ylabel('Density', fontsize=12)
    
    plt.axvline(h0_median, color='blue', linestyle='dashed', linewidth=1)
    plt.axvline(h1_median, color='red', linestyle='dashed', linewidth=1)
    
    # Add text annotation
    plt.text(0.65, 0.5, f"$\\Delta_{{coh}}$ (Median) = {delta_coh_median:.0f} cycles", 
             transform=plt.gca().transAxes, fontsize=12,
             bbox=dict(facecolor='white', alpha=0.8, edgecolor='gray'))

    plt.legend(loc='upper right')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    plt.savefig(OUT_IMG, dpi=300)
    print(f"Histogram saved to {OUT_IMG}")

if __name__ == '__main__':
    main()
