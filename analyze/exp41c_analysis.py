import csv
import numpy as np
import matplotlib.pyplot as plt

plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans'] # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False # 用来正常显示负号

import os

def load_csv(filepath):
    data = []
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return np.array([])
        
    with open(filepath, 'r') as f:
        reader = csv.reader(f)
        next(reader, None) # skip header
        for row in reader:
            if not row: continue
            try:
                data.append(float(row[0]))
            except ValueError:
                pass
    return np.array(data)

def print_stats(name, data):
    if len(data) == 0: return
    data = data[data < 2000] # filter huge outliers
    print(f"[{name}] Samples: {len(data)}, Mean: {np.mean(data):.1f}, Median: {np.median(data):.1f}, Std: {np.std(data):.1f}")
    return np.median(data)

def main():
    print("=== 分析: 4.1-B (Host-Guest, 跨 ASID) vs 4.1-C (Host-Only, 同 ASID) ===\n")
    
    # 4.1-B directory
    dir_41b = "<COHERE_REPO>/result/ch4/exp4_1_b"
    h0_41b = load_csv(os.path.join(dir_41b, "raw_h0_cycles.csv"))
    h1_41b = load_csv(os.path.join(dir_41b, "raw_h1_cycles.csv"))
    
    # 4.1-C directory
    dir_41c = "<COHERE_REPO>/result/ch4/exp4_1_c"
    h0_41c = load_csv(os.path.join(dir_41c, "host_only_h0.csv"))
    h1_41c = load_csv(os.path.join(dir_41c, "host_only_h1.csv"))
    
    print("【对照组 4.1-B：Host-Guest 跨 ASID】")
    med_h0_b = print_stats("4.1-B H0 (无访问)", h0_41b)
    med_h1_b = print_stats("4.1-B H1 (跨域一致性逐出)", h1_41b)
    if med_h0_b and med_h1_b:
        print(f" -> 逐出延迟差 (Delta_coh): {med_h1_b - med_h0_b:.1f} cycles\n")
        
    print("【实验组 4.1-C：Host-only 同 ASID 双视图】")
    med_h0_c = print_stats("4.1-C H0 (无访问)", h0_41c)
    med_h1_c = print_stats("4.1-C H1 (C-bit 逐出)", h1_41c)
    if med_h0_c and med_h1_c:
        print(f" -> 逐出延迟差 (Delta_coh): {med_h1_c - med_h0_c:.1f} cycles\n")

    # Plot Comparison TikZ data
    # (Generating Tikz instructions is basically writing out the bins and counts if needed)

if __name__ == '__main__':
    main()
