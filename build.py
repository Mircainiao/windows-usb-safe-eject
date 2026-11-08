"""Build the Windows x64 GUI. Run `build.ps1 onedir` before `build.ps1 onefile`."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys

from PIL import Image, ImageDraw
import PyInstaller
import PIL


ROOT = Path(__file__).resolve().parent
MODE = sys.argv[1] if len(sys.argv) == 2 else 'onedir'
CORE_SHA256 = '6c860342c0b97439db9149bf987e058e6f569a94467782e11ab9e8b679951c3c'
SMARTCTL_SHA256 = 'b5db94e5082c042be44994b7a4fa8f7b5c8e713b2ab1c9a560d8f7a7995ea27d'
SMARTMONTOOLS_SOURCE_SHA256 = '690b83ca331378da9ea0d9d61008c4b22dde391387b9bbad7f29387f2595f76e'

if sys.platform != 'win32' or struct.calcsize('P') * 8 != 64:
    raise SystemExit('请使用 64 位 Windows 和 64 位 Python 构建。')
if sys.version_info[:3] != (3, 14, 10):
    raise SystemExit('请使用与已验证版本一致的 Python 3.14.10 x64。')
if PyInstaller.__version__ != '6.22.3' or PIL.__version__ != '13.0.0':
    raise SystemExit('构建依赖版本不匹配；请使用 requirements-build-lock.txt。')
if MODE not in ('onedir', 'onefile'):
    raise SystemExit('参数必须为 onedir 或 onefile；先验收 onedir 再打 onefile。')
if hashlib.sha256((ROOT / 'safe_eject.py').read_bytes()).hexdigest() != CORE_SHA256:
    raise SystemExit('核心代码校验失败，拒绝打包未经复核的版本。')
if hashlib.sha256((ROOT / 'packaging/smartctl.exe').read_bytes()).hexdigest() != SMARTCTL_SHA256:
    raise SystemExit('smartctl 校验失败。')
if hashlib.sha256((ROOT / 'licenses/smartmontools-7.5.tar.gz').read_bytes()).hexdigest() != SMARTMONTOOLS_SOURCE_SHA256:
    raise SystemExit('smartmontools 对应源码归档校验失败。')

# Original, project-created geometric icon; no downloaded image assets.
canvas = Image.new('RGBA', (256, 256))
d = ImageDraw.Draw(canvas)
d.rounded_rectangle((22, 24, 234, 232), radius=30, fill='#183b56', outline='#58bac1', width=8)
d.ellipse((58, 50, 202, 194), fill='#b8d1df', outline='#f0f8ff', width=7)
d.ellipse((110, 102, 150, 142), fill='#254d64', outline='white', width=5)
d.line((135, 130, 194, 185), fill='#193b50', width=16)
d.ellipse((177, 167, 205, 195), fill='#31dbb1')
d.rounded_rectangle((49, 207, 115, 216), radius=4, fill='#70e3c4')
icon = ROOT / 'packaging/disk.ico'
canvas.save(icon, sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
canvas.save(ROOT / 'packaging/disk.png')

build_root = ROOT / 'build'
work = build_root / 'pyinstaller' / MODE
dist = build_root / 'onedir' if MODE == 'onedir' else ROOT / 'dist'
args = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--windowed',
        '--noupx', '--' + MODE, '--name', 'USB硬盘安全退出', '--paths', str(ROOT),
        '--icon', str(icon), '--workpath', str(work), '--specpath', str(build_root / 'spec'),
        '--distpath', str(dist),
        '--add-binary', str(ROOT / 'packaging/smartctl.exe') + ':tools',
        '--add-data', str(ROOT / 'safe_eject.py') + ':payload',
        '--add-data', str(ROOT / 'licenses') + ':licenses',
        '--add-data', str(icon) + ':.', str(ROOT / 'desktop_app.py')]
subprocess.run(args, check=True)
print(f'Build completed: {MODE}')
