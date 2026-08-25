# PABS-CRF 完整基准测试指南

## 概述

本目录包含完整的 PABS-CRF 基准测试套件，测试所有安全级别、属性数量、策略类型和优化配置。

## 测试覆盖范围

### ✅ 已包含的测试维度

| 维度 | 测试内容 |
|------|---------|
| **安全级别** | L1 (128-bit), L3 (192-bit), L5 (256-bit) |
| **属性数量** | 1, 3, 5, 10, 20 个属性 |
| **策略类型** | 单属性, 简单AND/OR, 复杂AND, 嵌套策略 |
| **操作类型** | Setup, KeyGen, Sign, Verify, Puncture |
| **优化** | Baseline, AVX-512 (如果CPU支持) |
| **缓存统计** | NTT缓存, 矩阵缓存的命中率 |
| **签名大小** | 原始, 结构化, 压缩格式 |
| **MLWE基线** | 无策略逻辑的核心性能 |

## 快速开始

### 1. 基础测试（无AVX-512）

```bash
cd /root/academic_implementation_v4
python3 scripts/run_comprehensive_benchmark.py --rounds 10
```

### 2. 完整测试（包括AVX-512）

```bash
python3 scripts/run_comprehensive_benchmark.py --rounds 10 --test-avx512
```

### 3. 快速烟雾测试（3轮）

```bash
python3 scripts/run_comprehensive_benchmark.py --rounds 3
```

## 命令行参数

```
--rounds N              运行N轮测试 (默认: 10)
--test-avx512           测试有/无AVX-512两种配置
--out-dir PATH          指定输出目录
--skip-build            跳过编译步骤
--timeout-sec N         每次运行的超时时间 (默认: 600秒)
```

## 输出文件结构

```
test-results/comprehensive/YYYYMMDD_HHMMSS/
├── environment.json              # 系统环境信息
├── run_config.json              # 运行配置
├── all_records.csv              # 所有测试记录（主要数据文件）
├── summary.json                 # 统计摘要
├── summary_metrics.csv          # 可读的统计摘要
├── records_baseline.jsonl       # Baseline配置的JSONL记录
├── records_avx512.jsonl         # AVX-512配置的JSONL记录（如果运行）
└── logs/                        # 详细日志
    ├── build_baseline.stdout.log
    ├── build_avx512.stdout.log
    ├── baseline_round_01.stdout.log
    ├── baseline_round_02.stdout.log
    └── ...
```

## 关键输出文件说明

### `all_records.csv`
包含每个测试的完整数据：
- 安全级别
- 属性数量
- 策略类型
- Sign/Verify时间
- 签名大小
- 缓存命中率
- Puncture性能
- 优化配置

### `summary.json`
跨所有测试的统计摘要：
- 平均值 (mean)
- 标准差 (stdev)
- 中位数 (median)
- 最小/最大值 (min/max)

## 测试的优化特性

### 1. NTT (Number Theoretic Transform)
- **位置**: `src/mlwe.rs`
- **功能**: 快速多项式乘法
- **缓存**: 预计算的NTT计划和矩阵NTT表示
- **测试**: 自动测试并报告缓存命中率

### 2. AVX-512 向量化
- **条件**: CPU支持 AVX-512F
- **编译**: `--features avx512`
- **加速**: 多项式运算的SIMD加速
- **测试**: 使用 `--test-avx512` 参数

### 3. 矩阵缓存
- **功能**: 缓存矩阵A的NTT变换
- **容量**: 32个条目
- **测试**: 报告命中/未命中统计

## 与原始测试的对比

### 原始 `run_aliyun_data_collection.py` (30% 覆盖率)
- ✅ Setup (仅L1)
- ✅ KeyGen (仅5个属性)
- ✅ Sign/Verify (仅简单AND策略)
- ✅ 签名大小
- ❌ 无Puncture测试
- ❌ 无多安全级别
- ❌ 无复杂策略
- ❌ 无AVX-512对比
- ❌ 无缓存统计

### 新 `run_comprehensive_benchmark.py` (100% 覆盖率)
- ✅ Setup (L1/L3/L5)
- ✅ KeyGen (1/3/5/10/20属性)
- ✅ Sign/Verify (单属性, AND, OR, 嵌套策略)
- ✅ 签名大小 (原始/结构化/压缩)
- ✅ **Puncture测试** (平均/最小/最大时间)
- ✅ **多安全级别对比**
- ✅ **复杂策略测试**
- ✅ **AVX-512 vs Baseline对比**
- ✅ **NTT和矩阵缓存统计**
- ✅ **MLWE核心基线**

## 预期运行时间

| 配置 | 轮数 | 预计时间 |
|------|-----|---------|
| Baseline only | 10 | ~20-30分钟 |
| Baseline + AVX-512 | 10 | ~40-60分钟 |
| Quick test (3 rounds) | 3 | ~10-15分钟 |

## 检查CPU是否支持AVX-512

```bash
# Linux
grep -o 'avx512[^ ]*' /proc/cpuinfo | sort -u

# 或者运行脚本会自动检测
python3 scripts/run_comprehensive_benchmark.py --test-avx512
# 如果不支持，会自动回退到baseline only
```

## 数据分析示例

### Python分析
```python
import pandas as pd

# 读取所有记录
df = pd.read_csv('test-results/comprehensive/YYYYMMDD_HHMMSS/all_records.csv')

# 按安全级别分组
print(df.groupby('security_level')['sign_ms'].describe())

# 按属性数量分组
print(df.groupby('keygen_attr_count')['keygen_ms'].mean())

# 对比AVX-512效果
baseline = df[df['config'] == 'baseline']['sign_ms'].mean()
avx512 = df[df['config'] == 'avx512']['sign_ms'].mean()
print(f"AVX-512 加速比: {baseline/avx512:.2f}x")

# 缓存命中率
print(f"NTT缓存命中率: {df['ntt_hit_rate'].mean():.2f}%")
```

## 故障排查

### 问题: 编译失败
```bash
# 清理并重新编译
cargo clean
cargo build --release --example comprehensive_perf_test
```

### 问题: 超时
```bash
# 增加超时时间
python3 scripts/run_comprehensive_benchmark.py --timeout-sec 1200
```

### 问题: 内存不足
- 确保至少有 4GB 可用内存
- 或减少轮数: `--rounds 5`

## 用于论文的建议配置

### 最小可接受配置
```bash
python3 scripts/run_comprehensive_benchmark.py --rounds 10
```

### 推荐配置（如果有AVX-512）
```bash
python3 scripts/run_comprehensive_benchmark.py --rounds 10 --test-avx512
```

### 完整配置（用于投稿）
```bash
# 运行20轮以获得更稳定的统计数据
python3 scripts/run_comprehensive_benchmark.py --rounds 20 --test-avx512
```

## 与其他方案的性能对比

测试会自动输出与 ML-DSA-44 (Dilithium2) 的对比表格，包括：
- Sign时间
- Verify时间
- 签名大小

## 致谢

本测试套件基于原始 `run_aliyun_data_collection.py` 扩展而来，增加了：
- 完整的参数集覆盖
- 优化配置测试
- 详细的性能分析
- 结构化数据收集
