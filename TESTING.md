# v1.0.0 验证记录

验证环境：Windows 11 x64、Python 3.14.10、PyInstaller 6.22.3。

## 自动化与构建

- `python -m py_compile safe_eject.py desktop_app.py build.py tests\test_safe_eject.py tests\test_desktop_wrapper.py`：核心程序、GUI 外壳、构建脚本和测试文件语法检查通过。
- `python -m unittest discover -s tests -v`：52 项通过，其中 44 项核心/ACL 测试（原有 39 项模拟测试、4 项 IPC ACL 模拟回归、1 项只操作临时文件的 Windows ACL 集成检查）和 8 项 GUI 外壳测试。
- 使用 Windows PowerShell 5.1 Parser 对生成的辅助程序 ACL 校验脚本做语法解析，通过；没有执行该脚本或注册任务。
- `build.ps1 onedir`：通过；随后 `build.ps1 onefile`：通过。依赖锁、Python x64、PyInstaller/Pillow 版本、核心源码、smartctl 和 smartmontools 源码归档哈希均由构建脚本核验。
- 对比发布前的核心源代码，`Disk`、`Native`、`VolumeIO`、`Profile`、`Smartctl` 和 `Backend` 代码块逐字节一致；本次核心差异只涉及辅助程序 IPC ACL、受保护版本号及升级校验。

## 文件夹版与单文件版

两种程序均复制到独立目录运行，环境中清空 `PATH`，并设置无效的 `PYTHONHOME`、`PYTHONPATH`。两种版本均通过：

- PE 为 AMD64、Windows GUI 子系统，包含程序图标；没有命令行窗口。
- GUI 打开并正常关闭；第二个并发实例被拒绝。
- 使用空设备清单模拟 USB 断开；过期身份被拒绝，窗口可关闭。
- 内置 smartctl 7.5 可启动；只读检测入口明确封堵本进程的缓存刷新、卷锁、卸载、停转和 PnP 弹出操作。
- 当前设备列表通过普通只读枚举读取；本测试只在本地保存原始诊断数据，没有纳入仓库或 Release。

本机现有授权任务是旧 helper v1，公开版使用 helper v2。因此打包验收没有调用助手，也未测试 v2 在本机安装/升级后的真实运行。版本 v2 的初始化、旧 ACL 迁移、请求/回复/临时文件访问策略由模拟测试覆盖；本轮没有 UAC 初始化，也没有修改现有计划任务或授权文件。

## 真实设备操作边界

上述模拟和打包验收均未对真实硬盘执行 `FlushFileBuffers`、锁卷、卸载、ATA/SAT 停转或 Windows PnP 移除。只读枚举及 SAT 身份查询可能唤醒休眠盘；本轮打包 smoke 只进行只读设备枚举，没有调用 SMART 身份查询。

维护者报告较早的本机私有版本曾完成一次安全移除操作。该人工记录不是公开 v1.0.0/helper v2 的实盘测试结果，也不证明实际机械停转或其他硬盘盒兼容。新版本首次安装和升级仍需用户在 GUI 发起并在 UAC 窗口明确同意；本轮没有执行。

## Release 文件

- `USB硬盘安全退出.exe`：15,410,017 bytes
- SHA-256：`edd09e12d9899aa85662330f14679ecac7335b01ffbed1e96e9b5471973e8f8f`
- GitHub 为兼容附件名会将直接下载的 EXE 命名为 `USB-Safe-Eject.exe` 并显示中文标签；`USB-Safe-Eject-v1.0.0.zip` 内保留 `USB硬盘安全退出.exe` 原名。
- 文件夹版 smoke SHA-256：`9e69e6ee1cb9fe34aa06c9cdd0c982382422ee2424c13c0f46750148b5b89cd1`
