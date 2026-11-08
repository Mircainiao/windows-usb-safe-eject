# Windows USB 硬盘安全退出

Windows 11 x64 中文小工具，用于识别外接 USB 磁盘、刷新并解除卷占用、请求 Windows 安全移除，并在硬盘盒支持标准 ATA/SAT 透传时尝试发送机械硬盘停转命令。

**Windows 显示安全移除成功，不代表已经独立确认机械硬盘完全停转。** 停转请求和 Windows PnP 移除结果分别报告；桥接芯片、驱动和硬盘固件会影响结果。本程序不会强制卸载被占用的卷，也不会使用未经验证的厂商命令。

## 下载

从 [GitHub v1.0.0 Release](https://github.com/Mircainiao/windows-usb-safe-eject/releases/tag/v1.0.0) 下载 `USB-Safe-Eject.exe`。GitHub 会规范化非 ASCII 附件名，直接 EXE 的页面标签为「USB硬盘安全退出.exe」。如果需要解压后保留中文文件名，请下载 `USB-Safe-Eject-v1.0.0.zip`；其中的程序文件名为 `USB硬盘安全退出.exe`。两种下载都面向 Windows 11 x64，均为单文件 GUI 程序，不需要为日常运行安装 Python。Release 同时提供 SHA-256 校验值及第三方许可证材料。

下载后可以在 PowerShell 中核对：

```powershell
Get-FileHash .\USB-Safe-Eject.exe -Algorithm SHA256
# 从压缩包解压后，也可以核对中文文件名
Get-FileHash .\USB硬盘安全退出.exe -Algorithm SHA256
```

将输出与 Release 页面和 `SHA256SUMS.txt` 中的值比较。当前 EXE 未进行 Authenticode 代码签名，Windows 可能显示来源提示；请只从本项目 Release 获取并校验。

## 功能

- 使用 Windows Storage/WMI 信息识别 USB 物理磁盘、型号、容量、所有分区盘符和挂载点。
- 通过设备实例、磁盘编号、总线类型、卷 extent 等信息复核目标；保守排除系统、启动、分页文件、内置、复合 USB 和身份不完整的设备。
- 在确认操作后刷新相关卷，逐一锁定卷；只在所有卷成功锁定后卸载卷。
- 尝试固定标准 ATA/SAT `STANDBY IMMEDIATE`，并读取一次硬盘待机报告。
- 关闭本程序句柄后请求 Windows PnP 安全移除整个 USB 设备。
- 遇到打开文件或锁卷失败时停止后续控制，不关闭其他程序，也不强制卸载。
- 把错误写入 `%LOCALAPPDATA%\UsbSafeEject\logs\desktop.log` 并显示提示。

操作大致顺序：重新识别 → 刷新缓存 → 锁定所有相关卷 → 验证并卸载卷 → 请求 ATA/SAT 停转 → 一次状态查询 → 关闭句柄 → 请求 Windows PnP 移除。锁卷失败会停止流程；停转命令失败时会分别报告，不会伪称机械停转成功。

## 使用步骤

1. 双击 EXE，以普通用户权限启动。
2. 等待列表刷新，核对目标硬盘型号、容量及全部分区盘符。
3. 点击「安全退出并停转」，完成只读身份检测；该检测可能唤醒休眠中的硬盘。
4. 再次点击按钮，在 Windows 确认框中核对设备身份并明确确认实际操作。
5. 等待结果。如果 Windows 没有报告设备安全移除成功，不要关闭硬盘盒电源。成功后再关闭硬盘盒电源，并等盘片完全停下后更换硬盘。

操作前请保存文件并关闭使用该盘的程序。确认和处理期间不要插拔设备或更换硬盘。若有程序占用卷，先关闭该程序，再刷新并重试。

## 兼容性与限制

已验证目标为 Windows 11 x64；其他 Windows 版本未在此版本中验证。适用设备需由 Windows 作为独立 USB 存储物理磁盘识别，并能可靠映射到物理盘、USB PnP 设备及其所有卷。主动停转还要求 USB-SATA 桥接芯片和驱动支持标准 SAT ATA 命令。

当前不支持或会保守拒绝动态磁盘、Storage Spaces、RAID、多物理盘复合 USB 设备、无法确认卷归属或设备身份的情形。设备被识别为“本地磁盘”本身既不表示兼容，也不表示不兼容。并非所有硬盘盒都支持停转命令；本项目没有宣称支持所有桥接芯片。

`STANDBY IMMEDIATE` 返回成功只表示命令调用路径完成。一次 `STANDBY` 状态报告只说明查询时硬盘报告待机。Windows 关闭句柄或 PnP 驱动仍可能再次访问设备，因此程序无法保证之后不会重新唤醒，也无法用软件独立测量物理主轴转速。实际机械停转状态无法确认时会明确显示「机械停转状态未知」。

## 权限和辅助任务

常规 GUI 以普通权限运行。需要锁卷和主动停转的功能由一次明确授权后安装在 `Program Files` 受保护目录中的固定辅助程序执行；任务以 SYSTEM 运行，但只接受固定的 `health`、只读 `inspect` 和受约束的 `eject` 请求。它会在每次实际操作前重新枚举并核验磁盘身份，不接收命令行、任意程序路径或任意 shell 命令。

**本 Release 中的 EXE 不会自动提权、初始化或修改计划任务。** 本机已存在的授权不会随 EXE 复制到其他电脑。新电脑首次配置需要使用可信源码运行初始化流程，并由用户在 Windows UAC 对话框中同意；UAC 会把当时运行的 Python 和源码复制到受保护目录。请先从本项目获取源码并核验其来源。源码运行要求安装 Windows x64 Python（包含 tkinter），并让 `smartctl` 可用；可临时把仓库内 `packaging` 加入 PATH：

```powershell
$env:Path = "$PWD\packaging;$env:Path"
python .\safe_eject.py
```

在首次点击操作按钮时，程序会说明授权范围。初始化只安装或更新助手，不会绕过后续实际磁盘确认；用户仍须在单独的设备确认框中点击确认才会控制磁盘。安装过程需要联网下载 Python 官方嵌入式运行包，并校验固定 SHA-256。初始化或更新都不会关闭 UAC、改变全局安全策略或授予任意管理员命令。

此机制不是对同一 Windows 账户恶意软件的防护：获授权 SID 下的其他进程也能提交这几种固定操作。GUI 确认主要用于避免日常误操作，不能替代 Windows 账户和软件来源安全。

已有 v1 辅助任务的用户应从可信源码运行 v1.0.0 的 `safe_eject.py` 并显式同意 UAC 更新。v2 会移除 IPC 请求、回复文件中其他本机用户可继承的读取权限；EXE 不会静默修改旧授权。更新时如果任务仍在运行，程序会拒绝更新。

## 从源码运行

项目核心逻辑只依赖 Python 标准库、Windows API 和 Windows PowerShell；不需要安装第三方 Python 运行时包。源代码运行还需要 `smartctl >= 7.5`，仓库已提供经固定 SHA-256 校验的 `packaging/smartctl.exe`，可按上一节临时加入 PATH。

```powershell
python -m pip install -r requirements.txt
$env:Path = "$PWD\packaging;$env:Path"
python .\safe_eject.py
```

`requirements.txt` 保持空的第三方运行依赖清单。源码中的 `--detect-only` 可用于只读枚举；该模式不锁卷、卸载、停转或弹出设备。SAT 身份查询可能唤醒休眠硬盘。

## 自行构建 EXE

在 Windows x64 上安装 Python 3.14.10 x64、Python Launcher 和 PowerShell，然后先构建并检查文件夹版，再构建单文件版：

```powershell
Set-Location .\windows-usb-safe-eject
.\build.ps1 onedir
.\build.ps1 onefile
```

脚本创建本地隔离构建环境，使用 `requirements-build-lock.txt` 固定依赖，并检查 Python 位数、PyInstaller/Pillow 版本、核心源码和 smartctl 哈希。文件夹版输出到 `build\onedir`，单文件 EXE 输出到 `dist`。构建和测试产物已被 `.gitignore` 排除。

构建依赖是 PyInstaller 6.22.3 和 Pillow 13.0.0。Pillow 只用于生成项目图标，不进入应用运行时。第三方组件和许可证范围见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 测试和验证范围

仓库的 44 项核心/ACL 测试和 8 项外壳测试不控制真实磁盘；其中 Windows ACL 集成检查只修改临时目录中的测试文件权限。打包验收已在 Windows 11 x64 上分别启动文件夹版和单文件版，验证 GUI 打开/关闭、重复启动拒绝、断开情形模拟、清空 PATH 后的内置 smartctl 定位及只读设备枚举；测试入口阻断了本进程的刷新缓存、锁卷、卸载、停转和 PnP 弹出。只读枚举可能唤醒设备，但没有改变磁盘状态。当前测试电脑的旧授权助手是 v1，因此没有调用新 v2 EXE 的助手，只验证了普通权限下的 GUI 和只读枚举。

维护者报告旧的本机私有版本曾完成一次 Windows 安全移除操作；该结果不等于本公开 v1.0.0 / 辅助程序 v2 已经完成真实硬盘控制验证，也不能外推到其他硬盘盒。v2 首次安装/升级只通过模拟测试，没有在本机实际更新现有授权。此次打包测试没有对真实硬盘执行锁卷、卸载、停转或弹出，且没有独立确认物理主轴停转。详细范围见 [TESTING.md](TESTING.md)。

## 安全声明

该程序会执行卷缓存刷新、卷锁定和卸载、ATA/SAT 电源命令及 Windows PnP 移除请求。磁盘身份和卷映射不能抵御被攻陷的 Windows 内核、驱动、桥接固件或硬件谎报。请仔细核对弹窗目标；不要在错误、超时或未确认安全移除时断电。

发现安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。不要在公开 Issue 中提交磁盘序列号、PnP 实例路径、用户名或完整本地日志。桌面日志可能包含设备型号和挂载路径，分享前请自行检查并脱敏。

## 许可证

本项目原创 Python 代码按 MIT License 发布。该许可证不覆盖 `smartctl`、Python/Tcl/Tk 运行时、PyInstaller 或其他第三方组件；其许可证和对应源码材料单独列于 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 `licenses/`。
