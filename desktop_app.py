"""打包外壳；safe_eject.py 的设备控制算法保持原样。"""
import ctypes as C
from ctypes import wintypes as W
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import shutil
from pathlib import Path
import subprocess
import sys
import threading
import traceback
tk = messagebox = core = None

BUNDLE = Path(getattr(sys, '_MEIPASS', Path(__file__).parent))
SOURCE = BUNDLE / 'payload/safe_eject.py'
if not SOURCE.exists():
    SOURCE = Path(__file__).with_name('safe_eject.py')
LOG_DIR = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'UsbSafeEject/logs'


def load_components():
    global tk, messagebox, core
    import tkinter as tk
    from tkinter import messagebox
    import safe_eject as core
    core.__file__ = str(SOURCE)


def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOG_DIR / 'desktop.log', maxBytes=1_000_000,
                                  backupCount=3, encoding='utf-8')
    logging.basicConfig(level=logging.INFO, handlers=[handler],
                        format='%(asctime)s %(levelname)s %(message)s')
    # EXE 单独复制也携带许可与对应 smartmontools 源码，启动后可直接查阅。
    if (BUNDLE / 'licenses').is_dir():
        shutil.copytree(BUNDLE / 'licenses', LOG_DIR.parent / 'licenses', dirs_exist_ok=True)
    # windowed EXE 没有 stdout/stderr；遗留诊断输出也写入日志。
    if sys.stdout is None:
        sys.stdout = open(LOG_DIR / 'stdio.log', 'a', encoding='utf-8', buffering=1)
    if sys.stderr is None:
        sys.stderr = sys.stdout


def show_failure(kind, value, tb):
    logging.error('Unhandled error', exc_info=(kind, value, tb))
    text = f'操作失败：{value}\n\n诊断日志：{LOG_DIR}\n未确认设备安全移除时，请勿断电。'
    try:
        messagebox.showerror('USB 硬盘安全退出', text)
    except Exception:
        C.windll.user32.MessageBoxW(None, text, 'USB 硬盘安全退出', 0x10)


def configure_frontend():
    if getattr(sys, 'frozen', False):
        # 不让外部系统工具继承 PyInstaller 的临时 DLL 搜索目录。
        k = C.WinDLL('kernel32', use_last_error=True)
        k.SetDllDirectoryW.argtypes = [W.LPCWSTR]
        if not k.SetDllDirectoryW(None):
            raise RuntimeError('无法清理外部工具的 DLL 搜索目录。')
    sys.excepthook = show_failure
    threading.excepthook = lambda args: show_failure(args.exc_type, args.exc_value, args.exc_traceback)
    tk.Tk.report_callback_exception = lambda self, kind, value, tb: show_failure(kind, value, tb)
    original_error = messagebox.showerror
    def handled_error(title=None, message=None, **kwargs):
        logging.error('GUI error: %s: %s', title, message)
        return original_error(title, message, **kwargs)
    messagebox.showerror = handled_error
    def bundled_smartctl(self):
        path = BUNDLE / 'tools/smartctl.exe'
        if not path.is_file() or core.file_hash(path) != core.SMART_HASH:
            raise core.SafetyError('集成 smartctl 缺失或校验失败，请重新获取完整软件。')
        self.exe = str(path)
    core.Smartctl.__init__ = bundled_smartctl

    # onefile 临时解包内容不可用作管理员安装入口，绝不 RunAs 此 EXE。
    def frozen_initialize(self):
        raise core.SafetyError('本机授权助手缺失或版本不兼容。便携版不会自动创建、更新或修改授权任务。'
                               '请先通过独立审核的初始化流程配置助手；请勿以管理员身份运行单文件 EXE。')
    core.HelperClient.initialize = frozen_initialize
    original_ask = messagebox.askyesno
    def ask(title=None, message=None, **kwargs):
        if title == '一次性授权配置':
            try:
                frozen_initialize(None)
            except core.SafetyError as error:
                messagebox.showerror('授权助手不可用', str(error), parent=kwargs.get('parent'))
            return False
        return original_ask(title, message, **kwargs)
    messagebox.askyesno = ask


def acquire_instance():
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateMutexW.argtypes, k.CreateMutexW.restype = [W.LPVOID, W.BOOL, W.LPCWSTR], W.HANDLE
    handle = k.CreateMutexW(None, False, 'Local\\UsbSafeEject.Desktop.v1')
    if not handle:
        raise RuntimeError('无法建立窗口单实例锁。')
    duplicate = C.get_last_error() == 183
    return handle, duplicate


def read_only_check(target, disconnected=False, hold=False):
    """打包验收专用，只允许 health/inspect；所有控制入口在进程内封堵。"""
    def blocked(*args, **kwargs):
        raise AssertionError('只读验收禁止真实磁盘控制')
    core.Backend.eject = blocked
    core.Native.request_eject = blocked
    for name in ('flush', 'lock', 'dismount'):
        setattr(core.VolumeIO, name, blocked)
    original_call = core.HelperClient.call
    def restricted(self, action, *args, **kwargs):
        if action not in ('health', 'inspect'):
            return blocked()
        return original_call(self, action, *args, **kwargs)
    core.HelperClient.call = restricted
    report = {'frozen': bool(getattr(sys, 'frozen', False)), 'bits': C.sizeof(C.c_void_p) * 8,
              'console_window': bool(C.windll.kernel32.GetConsoleWindow()),
              'log_directory': str(LOG_DIR), 'controls_blocked': True}
    smart = core.Smartctl()
    p = subprocess.run([smart.exe, '--version'], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    report['smartctl'] = p.stdout.decode('utf-8', errors='replace').splitlines()[0]
    report['smartctl_bundled'] = Path(smart.exe).is_relative_to(BUNDLE)
    helper = core.HelperClient()
    report['helper_ready'] = helper.ready()
    if report['helper_ready']:
        report['health'] = helper.call('health')
    backend = core.Backend()
    disks, rejected = backend.scan()
    report['disks'] = [{'number': d.number, 'model': d.model, 'size': d.size,
                        'paths': d.paths} for d in disks]
    report['rejected_count'] = len(rejected)
    if disks and report['helper_ready']:
        profile = helper.call('inspect', disks[0])
        report['ata'] = {k: profile[k] for k in ('model', 'size', 'rpm')}
    if disconnected and disks:
        # 模拟确认前断开，原 revalidate 必须拒绝旧身份。
        empty = core.Backend(reader=lambda: {'disks': [], 'physical': []})
        try:
            empty.revalidate(disks[0])
        except core.SafetyError:
            report['disconnect_rejected'] = True
        else:
            raise AssertionError('断开后未拒绝过期身份')
    original_tk = tk.Tk
    def window():
        root = original_tk()
        root.iconbitmap(str(BUNDLE / 'disk.ico'))
        original_destroy = root.destroy
        def destroyed():
            report['window_closed'] = True
            original_destroy()
        root.destroy = destroyed
        def close_when_ready():
            # 调用原窗口关闭处理；只读测试不点击安全退出按钮。
            root.tk.call(root.protocol('WM_DELETE_WINDOW'))
        root.after(20000 if hold else 8000, close_when_ready)
        report['gui_opened'] = True
        return root
    tk.Tk = window
    if disconnected:
        core.Backend.scan = lambda self: ([], [])
    core.main(auto_confirm=False)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    logging.info('Read-only packaging check completed: %s', target)


def entry():
    setup_logging()
    load_components()  # 导入/Tk DLL 故障也由外层异常处理记录并提示。
    configure_frontend()
    logging.info('Desktop start frozen=%s', bool(getattr(sys, 'frozen', False)))
    if core.admin():
        raise core.SafetyError('请以普通权限启动本便携版；特权操作由已有受保护助手完成。')
    if len(sys.argv) >= 3 and sys.argv[1] == '--package-check':
        import re
        if ('--allow-readonly-probe' not in sys.argv
                or not re.fullmatch(r'[a-z0-9-]{1,80}\.json', sys.argv[2])):
            raise core.SafetyError('诊断需明确启用只读检测，并使用简单 JSON 文件名；不接受任意报告路径。')
        target = LOG_DIR / 'package-tests' / sys.argv[2]
        target.parent.mkdir(exist_ok=True)
        handle, duplicate = acquire_instance()
        try:
            if duplicate:
                target.write_text(json.dumps({'duplicate_rejected': True}), encoding='utf-8')
                return
            read_only_check(target, '--disconnected' in sys.argv, '--hold' in sys.argv)
        finally:
            k = C.WinDLL('kernel32')
            k.CloseHandle.argtypes = [W.HANDLE]
            k.CloseHandle(handle)
        return
    if sys.argv[1:]:
        raise core.SafetyError('不支持的启动参数。请直接双击运行。')
    handle, duplicate = acquire_instance()
    try:
        if duplicate:
            logging.warning('Duplicate launch rejected')
            messagebox.showinfo('USB 硬盘安全退出', '程序已经运行，请使用已打开的窗口。')
            return
        original_tk = tk.Tk
        def window():
            root = original_tk()
            root.iconbitmap(str(BUNDLE / 'disk.ico'))
            return root
        tk.Tk = window
        core.main()
        logging.info('Window closed normally')
    finally:
        k = C.WinDLL('kernel32')
        k.CloseHandle.argtypes = [W.HANDLE]
        k.CloseHandle(handle)


if __name__ == '__main__':
    try:
        entry()
    except Exception:
        show_failure(*sys.exc_info())
        raise SystemExit(1)
