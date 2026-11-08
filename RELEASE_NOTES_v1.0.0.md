# USB 硬盘安全退出 v1.0.0

- 适用平台：Windows 11 x64。
- 附件：`USB硬盘安全退出.exe`，PyInstaller 单文件 GUI 程序；`third-party-materials-v1.0.0.zip`，包含第三方许可证、声明和 smartmontools 对应源码归档。
- SHA-256：`edd09e12d9899aa85662330f14679ecac7335b01ffbed1e96e9b5471973e8f8f`。
- 第三方许可：smartmontools 7.5 的 GPL 许可证和对应源码随 EXE 内置，并另附在仓库 `licenses/`。
- 日常运行使用普通权限；未配置辅助任务的新电脑需要从可信源码进行一次显式 UAC 初始化。发布 EXE 不会自动创建或修改授权任务。
- 主动停转受硬盘盒、桥接芯片、驱动和固件支持影响。Windows 安全移除成功不等于物理停转已确认。
- 52 项自动化测试和文件夹版/单文件版只读 GUI 验收通过；包括仅操作临时文件的 Windows ACL 集成检查。没有锁定、卸载、停转或弹出真实硬盘。维护者报告旧本机版本曾完成一次安全移除，本公开版 v2 辅助任务未在真实磁盘上验证。
- `SHA256SUMS.txt` 同时列出 EXE 与第三方许可材料压缩包的 SHA-256。
- 本 EXE 未进行 Authenticode 代码签名。下载后请用 `SHA256SUMS.txt` 校验。
