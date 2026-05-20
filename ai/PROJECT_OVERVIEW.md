# hashcat 项目分析文档（面向 AI 辅助开发）

> **项目简介**：hashcat 是世界上最快、最先进的密码恢复工具，支持 300+ 种哈希算法，可在 CPU、GPU 及其他硬件加速器上运行。使用 C 语言编写（gnu99 标准），采用 MIT 许可证。

---

## 1. 项目整体架构

```
hashcat/
├── src/              # 核心 C 源码（约 130 个文件）
├── include/          # 头文件（约 78 个文件）
├── modules/          # 哈希模块（.so 共享库，约 350+ 个）
├── OpenCL/           # GPU 内核（.cl 文件，约 1500+ 个）
├── Rust/             # 下一代插件系统（Rust FFI）
│   ├── hashcat-sys/  # 底层 FFI 绑定
│   ├── bridges/      # 桥接插件（连接外部计算后端）
│   └── feeds/        # 馈送插件（连接外部候选生成器）
├── Python/           # Python 工具和原型
├── tools/            # 40+ 个实用脚本（哈希提取/转换/测试）
├── deps/             # 第三方依赖
├── docs/             # 文档（含插件开发指南）
├── rules/            # 规则文件
├── masks/            # 掩码攻击定义
├── charsets/         # 字符集文件
├── layouts/          # 键盘布局映射
├── tunings/          # 调优数据库
├── bridges/          # 桥接配置
├── feeds/            # 馈送配置
├── kernels/          # （空目录，曾用于存放编译后内核）
├── docker/           # Docker 构建配置
├── extra/            # 额外资源文件
└── AI/               # AI 辅助开发文档（本目录）
```

---

## 2. 核心入口与主循环

### 2.1 `src/main.c` — 程序入口

```C
int main (int argc, char **argv)  // 第 1338 行
```

执行流程：
1. `setup_console()` — 控制台设置
2. `hashcat_init(hashcat_ctx, event)` — 创建核心上下文
3. `user_options_init()` — 初始化用户选项
4. `user_options_getopt()` — 解析命令行参数
5. `user_options_postprocess()` — 参数后处理
6. `hashcat_session_init()` — 会话初始化（加载模块、检测设备等）
7. `hashcat_session_execute()` — 执行破解
8. 清理和退出

### 2.2 `src/hashcat.c` — 会话管理

核心函数调用链：

```
hashcat_session_init()
  → module_load()          # 加载指定哈希模块
  → backend_init()         # 初始化后端（CUDA/HIP/Metal/OpenCL）
  → backend_opencl_init()  # 发现计算设备
  → bridges_init()         # 初始化桥接
  → ...

hashcat_session_execute()
  → autodetect_hashmodes() # 自动检测哈希模式
  → selftest()             # 自检
  → autotune()             # 自动调优
  → outer_loop()           # 主破解循环
    → inner1_loop()
      → inner2_loop()
        → run_kernel()     # 在 GPU/CPU 上执行内核
```

### 2.3 事件驱动架构

所有日志、UI 更新、生命周期通知通过 `event()` 函数分发（`src/main.c:1265`）。事件类型定义在 `include/types.h` 的 `event_identifier_t` 枚举中（第 100-175 行），如：
- `EVENT_CRACKER_STARTING` / `EVENT_CRACKER_FINISHED` — 破解开始/结束
- `EVENT_CRACKER_HASH_CRACKED` — 哈希被破解
- `EVENT_MONITOR_STATUS_REFRESH` — 状态刷新
- `EVENT_SELFTEST_STARTING` / `EVENT_SELFTEST_FINISHED` — 自检
- 等等

---

## 3. 核心数据结构

### 3.1 全局上下文 `hashcat_ctx_t`（`include/types.h:3236-3272`）

这是贯穿整个程序的核心结构体，包含所有子系统的上下文指针：

| 字段 | 子系统 | 职责 |
|------|--------|------|
| `brain_ctx` | 分布式 | 分布式破解协调 |
| `bitmap_ctx` | 位图 | 布隆过滤器，快速哈希淘汰 |
| `bridge_ctx` | 桥接 | 桥接插件上下文 |
| `combinator_ctx` | 组合攻击 | 组合攻击状态 |
| `cpt_ctx` | 破解时间 | 破解时间统计 |
| `debugfile_ctx` | 调试 | 调试文件输出 |
| `dictstat_ctx` | 字典统计 | 字典缓存 |
| `event_ctx` | 事件 | 事件缓冲 |
| `folder_config` | 路径 | 安装/配置/缓存/会话目录 |
| `generic_ctx` | 通用插件 | 通用攻击模式插件 |
| `hashconfig` | 哈希配置 | 当前哈希模式配置 |
| `hashes` | 哈希列表 | 待破解的哈希 |
| `hwmon_ctx` | 硬件监控 | 温度/风扇/功耗监控 |
| `induct_ctx` | 归纳 | 字典归纳（循环） |
| `logfile_ctx` | 日志 | 日志文件 |
| `loopback_ctx` | 回环 | 回环字典 |
| `mask_ctx` | 掩码 | 掩码/BF 攻击状态 |
| `module_ctx` | 模块 | 动态加载的哈希模块 |
| `backend_ctx` | 后端 | 设备管理 |
| `outcheck_ctx` | 输出检查 | 输出目录检查 |
| `outfile_ctx` | 输出文件 | 破解结果输出 |
| `pidfile_ctx` | PID | PID 文件 |
| `potfile_ctx` | Potfile | 已破解哈希记录 |
| `restore_ctx` | 恢复 | 会话恢复 |
| `status_ctx` | 状态 | 运行时状态 |
| `straight_ctx` | 直连攻击 | 字典攻击状态 |
| `tuning_db` | 调优 | 设备调优数据库 |
| `user_options` | 用户选项 | 命令行参数 |
| `user_options_extra` | 额外选项 | 派生的用户选项 |
| `wl_data` | 字典数据 | 字典文件读写状态 |

### 3.2 设备参数 `hc_device_param_t`（`include/types.h:1264-1985`）

这是最复杂的结构体之一（~720 行），统一抽象了 CUDA、HIP、Metal、OpenCL 四种后端：

- **通用字段**：`device_id`、`device_name`、`device_processors`、`kernel_accel/loops/threads` 等
- **CUDA 特定**：`is_cuda`、`cuda_device`、`cuda_context`、`cuda_function*`、`cuda_d_*`（设备内存指针）
- **HIP 特定**：`is_hip`、`hip_device`、`hip_context`、`hip_function*`、`hip_d_*`
- **Metal 特定**：`is_metal`、`is_apple_silicon`、`metal_device`、`metal_function*`、`metal_d_*`
- **OpenCL 特定**：`is_opencl`、`opencl_device`、`opencl_kernel*`、`opencl_d_*`

### 3.3 哈希配置 `hashconfig_t`（`include/types.h:1123-1203`）

定义哈希模式的所有属性：`hash_mode`、`hash_name`、`dgst_size`、`opti_type`、`opts_type`、`pw_min/pw_max`、`salt_min/salt_max`、内核调优参数范围等。

### 3.4 模块接口 `module_ctx_t`（`include/types.h:3136-3234`）

动态加载的哈希模块导出的函数指针表，包含 60+ 个函数指针：
- 基础信息：`module_hash_name`、`module_hash_mode`、`module_hash_category`
- 参数配置：`module_pw_min/max`、`module_salt_min/max`、`module_kernel_accel/loops/threads_min/max`
- 编解码：`module_hash_encode`、`module_hash_decode`、`module_hash_encode_potfile` 等
- 调优与自检：`module_st_hash`、`module_st_pass`、`module_extra_tuningdb_block`
- 钩子：`module_hook12`、`module_hook23`
- JIT 编译：`module_jit_build_options`、`module_jit_cache_disable`
- 桥接：`module_bridge_type`、`module_bridge_name`

---

## 4. 攻击模式

定义在 `include/types.h` 的 `attack_mode_t` 枚举（第 266-280 行）：

| 模式 | 枚举值 | 说明 |
|------|--------|------|
| 0 | `ATTACK_MODE_STRAIGHT` | 字典攻击（Wordlist） |
| 1 | `ATTACK_MODE_COMBI` | 组合攻击（Combinator） |
| 3 | `ATTACK_MODE_BF` | 暴力破解/掩码攻击（Brute-Force/Mask） |
| 6 | `ATTACK_MODE_HYBRID1` | 混合攻击：字典+掩码 |
| 7 | `ATTACK_MODE_HYBRID2` | 混合攻击：掩码+字典 |
| 9 | `ATTACK_MODE_ASSOCIATION` | 关联攻击 |
| 10 | `ATTACK_MODE_GENERIC` | 通用插件攻击模式 |

内核级攻击类型 `attack_kern_t`（第 282-289 行）：
- `ATTACK_KERN_STRAIGHT` — 直连内核
- `ATTACK_KERN_COMBI` — 组合内核
- `ATTACK_KERN_BF` — 暴力破解内核（含掩码）

---

## 5. 后端抽象层

### 5.1 支持的硬件后端

| 后端 | 源文件 | 说明 |
|------|--------|------|
| OpenCL | `ext_OpenCL.c` | 跨平台 GPU/CPU 计算 |
| CUDA | `ext_cuda.c`、`ext_nvrtc.c` | NVIDIA GPU |
| HIP | `ext_hip.c`、`ext_hiprtc.c` | AMD GPU (ROCm) |
| Metal | `ext_metal.m` | Apple GPU |

### 5.2 硬件监控

| 后端 | 源文件 | 说明 |
|------|--------|------|
| NVML | `ext_nvml.c` | NVIDIA 管理库 |
| NVAPI | `ext_nvapi.c` | NVIDIA API |
| ADL | `ext_ADL.c` | AMD 显示库 |
| sysfs/amdgpu | `ext_sysfs_amdgpu.c` | AMD GPU sysfs |
| sysfs/intel | `ext_sysfs_intelgpu.c` | Intel GPU sysfs |
| sysfs/cpu | `ext_sysfs_cpu.c` | CPU sysfs |
| IOKit | `ext_iokit.m` | macOS IOKit |

---

## 6. 内核执行管道

内核分为多阶段执行，定义在 `kern_run_t` 枚举（`include/types.h:291-309`）：

```
KERN_RUN_1    → 第一阶段（amp/preprocess）
KERN_RUN_12   → 1→2 转换
KERN_RUN_2    → 第二阶段（主计算）
KERN_RUN_23   → 2→3 转换
KERN_RUN_3    → 第三阶段（后处理/比较）
KERN_RUN_4    → 第四阶段（附加比较）
KERN_RUN_INIT2 → 初始化第二阶段
KERN_RUN_LOOP2 → 循环第二阶段（迭代哈希）
KERN_RUN_AUX1~4 → 辅助内核
```

钩子函数 `HOOK12`/`HOOK23` 允许特定哈希模式在阶段之间插入自定义转换逻辑。

---

## 7. OpenCL 内核系统

### 7.1 命名约定

```
OpenCL/mXXXXX_aY-{optimized|pure}.cl
```

- `XXXXX` = 哈希模式编号
- `Y` = 攻击模式（0=straight, 1=combinator, 3=brute-force）
- `optimized` = 手工优化的内核变体
- `pure` = 参考/未优化变体

### 7.2 共享包含文件

| 类别 | 文件前缀 | 示例 |
|------|----------|------|
| 哈希函数 | `inc_hash_*.cl` | `inc_hash_md5.cl`、`inc_hash_sha1.cl`、`inc_hash_sha256.cl` 等 |
| 密码算法 | `inc_cipher_*.cl` | `inc_cipher_aes.cl`、`inc_cipher_des.cl`、`inc_cipher_serpent.cl` 等 |
| 磁盘加密 | `inc_luks_*.cl`、`inc_truecrypt_*.cl`、`inc_veracrypt_*.cl` | LUKS/TrueCrypt/VeraCrypt 相关 |
| 规则引擎 | `inc_rp.cl`、`inc_rp_optimized.cl` | GPU 端规则处理器 |
| 公共 | `inc_common.cl`、`inc_platform.cl`、`inc_simd.cl` | 公共宏和平台定义 |
| 比较 | `inc_comp_single.cl`、`inc_comp_multi.cl` | 单/多哈希比较逻辑 |
| 放大器 | `amp_a0.cl`、`amp_a1.cl`、`amp_a3.cl` | 词放大器内核 |

### 7.3 共享内核

- `shared.cl` — 所有内核间共享的 GPU 工具函数
- `markov_le.cl` / `markov_be.cl` — Markov 模型（小端/大端）

---

## 8. 模块系统

### 8.1 模块加载

- `src/dynloader.c` — 动态加载器，通过 `dlopen()/LoadLibrary()` 加载 `.so/.dll`
- 模块位于 `modules/` 目录
- 命名：`module_XXXXX.so`（XXXXX = 哈希模式编号）
- 每个模块导出 `MODULE_INIT` 函数指针来初始化 `module_ctx_t`
- 附带 `.su` 文件（自检校验和）

### 8.2 模块源文件位置

模块源码在 `src/modules/` 目录下，每个哈希模式有独立的 `.c` 源文件。

---

## 9. 关键子系统详解

### 9.1 位图（Bitmap）

- `src/bitmap.c` + `include/bitmap.h`
- 实现布隆过滤器，在 GPU 计算前快速排除不匹配的哈希
- 两层结构（s1/s2），每层 4 个 32 位数组（a/b/c/d）

### 9.2 规则引擎

- `src/rp.c` + `src/rp_cpu.c` + `OpenCL/inc_rp*.cl`
- 支持 80+ 种规则操作（定义在 `rule_functions_t` 枚举，`include/types.h:319-401`）
- 可在 CPU（`rp_cpu.c`）或 GPU（OpenCL 内核）上执行
- 支持规则文件、随机规则生成（`rp_gen`）

### 9.3 分布式破解（Brain）

- `src/brain.c` + `include/brain.h`
- 客户端-服务器模型，通过 TCP 协调多台机器
- 共享已破解密码，避免重复工作

### 9.4 字典统计（Dictstat）

- `src/dictstat.c` + `include/dictstat.h`
- 缓存字典文件元数据，加速重复运行

### 9.5 自动调优

- `src/autotune.c` — 运行时自动调优内核参数
- `src/tuningdb.c` — 调优数据库（预存设备-模式最佳参数）
- 对每个设备/哈希模式组合寻找最佳 `kernel_accel`、`kernel_loops`、`kernel_threads`

### 9.6 自检（Selftest）

- `src/selftest.c`
- 使用模块提供的 `module_st_hash` 和 `module_st_pass` 验证哈希计算正确性

---

## 10. 源文件速查表

### 10.1 核心流程

| 文件 | 职责 |
|------|------|
| `src/main.c` | 入口点、事件处理、日志、UI |
| `src/hashcat.c` | 会话生命周期管理 |
| `src/hashcat.h` | （`include/hashcat.h`）公共 API 头文件 |
| `src/dispatch.c` | 内核调度和工作分配 |
| `src/backend.c` | 后端设备管理 |
| `src/interface.c` | 命令行交互界面 |
| `src/user_options.c` | 命令行参数解析 |
| `src/usage.c` | 帮助信息生成 |

### 10.2 攻击模式

| 文件 | 攻击模式 |
|------|----------|
| `src/straight.c` | 字典攻击（模式 0） |
| `src/combinator.c` | 组合攻击（模式 1） |
| `src/mask.c` + `src/mpsp.c` | 掩码/Markov 攻击（模式 3） |
| `src/stdout.c` | 候选输出模式 |
| `src/slow_candidates.c` | 慢速候选模式 |

### 10.3 规则系统

| 文件 | 职责 |
|------|------|
| `src/rp.c` | 规则解析器和引擎核心 |
| `src/rp_cpu.c` | CPU 端规则执行 |
| `src/keyboard_layout.c` | 键盘布局映射 |

### 10.4 数据处理

| 文件 | 职责 |
|------|------|
| `src/hashes.c` | 哈希列表管理 |
| `src/hlfmt.c` | 哈希格式解析（pwdump/shadow/DCC 等） |
| `src/convert.c` | 编码转换（UTF-8/UTF-16/Base64 等） |
| `src/bitmap.c` | 布隆过滤器 |
| `src/shared.c` | 共享工具函数 |
| `src/common.c` | 通用帮助函数 |
| `src/memory.c` | 内存管理 |

### 10.5 文件 I/O

| 文件 | 职责 |
|------|------|
| `src/filehandling.c` | 文件打开/读/写（支持 gz/xz/unrar） |
| `src/folder.c` | 目录配置管理 |
| `src/potfile.c` | 破解结果持久化 |
| `src/outfile.c` | 结果输出 |
| `src/outfile_check.c` | 输出目录监控 |
| `src/logfile.c` | 日志记录 |
| `src/restore.c` | 会话恢复 |
| `src/pidfile.c` | PID 文件管理 |
| `src/wordlist.c` | 字典文件读取 |
| `src/dictstat.c` | 字典统计缓存 |
| `src/loopback.c` | 回环字典 |
| `src/induct.c` | 字典归纳/循环 |

### 10.6 后端

| 文件 | 后端 |
|------|------|
| `src/ext_OpenCL.c` | OpenCL 后端 |
| `src/ext_cuda.c` | CUDA 后端 |
| `src/ext_hip.c` | HIP/ROCm 后端 |
| `src/ext_metal.m` | Metal/Apple 后端 |
| `src/ext_nvrtc.c` | NVIDIA 运行时编译 |
| `src/ext_hiprtc.c` | HIP 运行时编译 |
| `src/ext_lzma.c` | LZMA 压缩支持 |

### 10.7 硬件监控

| 文件 | 职责 |
|------|------|
| `src/hwmon.c` | 硬件监控统一接口 |
| `src/ext_nvml.c` | NVIDIA 管理库 |
| `src/ext_nvapi.c` | NVIDIA API |
| `src/ext_ADL.c` | AMD 显示库 |
| `src/ext_sysfs_amdgpu.c` | AMD GPU sysfs |
| `src/ext_sysfs_intelgpu.c` | Intel GPU sysfs |
| `src/ext_sysfs_cpu.c` | CPU sysfs |
| `src/ext_iokit.m` | macOS IOKit |

### 10.8 模拟器（用于调试和纯 CPU 内核）

| 文件 | 职责 |
|------|------|
| `src/emu_general.c` | 通用模拟器基础设施 |
| `src/emu_inc_hash_*.c` | 各种哈希函数的 CPU 模拟实现 |
| `src/emu_inc_cipher_*.c` | 各种密码算法的 CPU 模拟实现 |
| `src/emu_inc_rp*.c` | 规则引擎的 CPU 模拟实现 |
| `src/emu_inc_simd.c` | SIMD 操作的 CPU 模拟 |
| `src/emu_inc_scalar.c` | 标量操作的 CPU 模拟 |
| `src/emu_inc_platform.c` | 平台抽象模拟 |
| `src/emu_inc_common.c` | 通用模拟 |

### 10.9 其他

| 文件 | 职责 |
|------|------|
| `src/affinity.c` | CPU 亲和性设置 |
| `src/autotune.c` | 内核自动调优 |
| `src/tuningdb.c` | 调优数据库 |
| `src/benchmark.c` | 基准测试 |
| `src/selftest.c` | 自检 |
| `src/brain.c` | 分布式破解客户端/服务器 |
| `src/bridges.c` | 桥接管理 |
| `src/cpt.c` | 破解时间统计 |
| `src/debugfile.c` | 调试文件 |
| `src/dynloader.c` | 动态库加载 |
| `src/event.c` | 事件系统 |
| `src/bitops.c` | 位操作工具 |
| `src/cpu_crc32.c` | CPU CRC32 |
| `src/cpu_features.c` | CPU 特性检测 |
| `src/generic.c` | 通用攻击模式插件 |
| `src/locking.c` | 线程锁 |
| `src/monitor.c` | 运行时监控（温度/性能） |
| `src/status.c` | 状态报告生成 |
| `src/terminal.c` | 终端交互 |
| `src/thread.c` | 线程管理 |
| `src/timer.c` | 计时器 |

---

## 11. 构建系统

- **主构建**：GNU `Makefile`（项目根目录）
- **子构建**：`src/Makefile`
- **支持平台**：macOS (`BUILD_macOS.md`)、Linux、Windows MSYS2 (`BUILD_MSYS2.md`)、Cygwin (`BUILD_CYGWIN.md`)、WSL (`BUILD_WSL.md`)、Android (`BUILD_Android.md`)、Docker (`BUILD_Docker.md`)
- **编译器要求**：GCC 或 Clang，`-std=gnu99`
- **第三方依赖**（均在 `deps/` 下）：LZMA-SDK、OpenCL-Headers、Argon2、scrypt-jane、xxHash、yescrypt、zlib、unrar、sse2neon

---

## 12. 扩展点

### 12.1 添加新哈希模式

1. 在 `src/modules/` 下创建 `module_XXXXX.c`
2. 实现 `MODULE_INIT` 函数，填充 `module_ctx_t` 各字段
3. 实现 `module_hash_encode/decode` 等必要函数
4. 创建 OpenCL 内核 `OpenCL/mXXXXX_a0-pure.cl`、`-optimized.cl`、`a1`、`a3` 变体
5. 更新 `src/Makefile` 添加编译目标
6. 参考文档：`docs/hashcat-plugin-development-guide.md`

### 12.2 添加桥接（Bridge）

- 桥接允许连接外部计算后端
- Rust 实现位于 `Rust/bridges/`
- 配置位于 `bridges/`
- C 端接口定义在 `src/bridges.c` 和 `include/bridges.h`
- 参考文档：`docs/hashcat-assimilation-bridge-development.md`

### 12.3 添加馈送（Feed）

- 馈送允许连接外部候选生成器
- Rust 实现位于 `Rust/feeds/`
- 配置位于 `feeds/`

### 12.4 Python 插件

- 通过 `Python/` 中的 `hcsp.py`（会话协议）和 `hcmp.py`（管理协议）
- 参考文档：`docs/hashcat-python-plugin-development-guide.md`

---

## 13. 代码风格约定

来自 `README.md` 的贡献指南：

1. MIT 许可证
2. 遵循 gnu99 标准
3. 使用 `-W -Wall -std=gnu99` 无警告编译
4. **Allman 风格**代码块和缩进
5. 使用 **2 空格**缩进（Makefile 中可用 Tab）
6. 小写函数名和变量名
7. 避免使用 `!`，使用正向条件（如 `if (foo == 0)` 而非 `if (!foo)`）
8. 使用 `array[index + 0]` 风格保持对齐

可使用 GNU Indent 自动格式化：
```sh
indent -st -bad -bap -sc -bl -bli0 -ncdw -nce -cli0 -cbi0 -pcs -cs -npsl -bs -nbc -bls -blf -lp -i2 -ts2 -nut -l1024 -nbbo -fca -lc1024 -fc1
```

---

## 14. 关键枚举速查

### 哈希类别（`hash_category_t`，`include/types.h:3330-3357`）

`RAW_HASH`, `RAW_HASH_SALTED`, `RAW_HASH_AUTHENTICATED`, `RAW_CHECKSUM`, `RAW_CIPHER_KPA`, `GENERIC_KDF`, `NETWORK_PROTOCOL`, `OS`, `DATABASE_SERVER`, `NETWORK_SERVER`, `EAS`, `FDE`, `DOCUMENTS`, `PASSWORD_MANAGER`, `ARCHIVE`, `FORUM_SOFTWARE`, `OTP`, `PLAIN`, `FRAMEWORK`, `PRIVATE_KEY`, `IMS`, `CRYPTOCURRENCY_WALLET`, `FBE`, `APPLICATION_DATABASE`

### 优化类型（`opti_type_t`，`include/types.h:412-441`）

`OPTIMIZED_KERNEL`, `ZERO_BYTE`, `PRECOMPUTE_INIT`, `MEET_IN_MIDDLE`, `EARLY_SKIP`, `NOT_SALTED`, `NOT_ITERATED`, `PREPENDED_SALT`, `APPENDED_SALT`, `SINGLE_HASH`, `SINGLE_SALT`, `BRUTE_FORCE`, `RAW_HASH`, `SLOW_HASH_SIMD_*`, `USES_BITS_*`, `REGISTER_LIMIT`

### 状态码（`status_rc_t`，`include/types.h:216-234`）

`STATUS_INIT` → `STATUS_AUTOTUNE` → `STATUS_SELFTEST` → `STATUS_RUNNING` → `STATUS_PAUSED` / `STATUS_EXHAUSTED` / `STATUS_CRACKED` / `STATUS_ABORTED` / `STATUS_QUIT` / `STATUS_BYPASS` / `STATUS_ERROR`

---

## 15. Rust 子系统概览

```
Rust/
├── hashcat-sys/    # -sys crate: C FFI 绑定
│   └── src/        # 绑定到 hashcat.h 的 C API
├── bridges/        # 桥接插件工作区成员
│   └── src/        # 桥接实现
└── feeds/          # 馈送插件工作区成员
    └── src/        # 馈送实现
```

Rust 桥接是 v7.x 引入的下一代扩展机制，允许用 Rust 编写高性能的扩展后端和候选生成器。

---

## 16. 快速导航（对 AI 最重要的文件）

调试和理解问题时，建议按以下优先级阅读：

1. **`include/types.h`** — 所有数据结构定义，理解项目的关键
2. **`src/main.c`** — 入口点和事件处理
3. **`src/hashcat.c`** — 会话生命周期
4. **`src/dispatch.c`** — 内核调度逻辑
5. **`src/backend.c`** — 设备后端管理
6. **`src/user_options.c`** — 命令行参数解析
7. **`src/hashes.c`** + **`src/hlfmt.c`** — 哈希解析
8. **`OpenCL/inc_common.cl`** + **`OpenCL/shared.cl`** — GPU 内核基础

---

> **最后更新**：2025-07-15
> **维护说明**：本文档随项目演进需要同步更新。当项目结构发生重大变化（如新增目录、重构模块系统、更新版本号等）时，请更新对应章节。
