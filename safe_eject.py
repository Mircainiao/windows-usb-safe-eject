"""Windows USB HDD：先只读检测，经确认后锁卷、标准 SAT 停转及 PnP 移除。

需要 smartctl >= 7.5；只用 -d sat，不用厂商命令。不证明实际机械停转。
python safe_eject.py --detect-only 仅识别/检测，不刷新、锁卷、卸载或停转。
"""
import base64
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass, asdict
import json
import os
import queue
import subprocess
import threading
import re
import shutil
import struct
import sys
import time
import uuid
import hashlib
import zipfile
import urllib.request
from contextlib import contextmanager
from pathlib import Path


class SafetyError(RuntimeError):
    pass


class DeviceError(SafetyError):
    def __init__(self, message, category='操作失败', code=None):
        super().__init__(f'{category}：{message}')
        self.category, self.code = category, code


def admin():
    return bool(C.windll.shell32.IsUserAnAdmin()) if os.name == 'nt' else False


def system_tool(relative):
    k = C.WinDLL('kernel32', use_last_error=True)
    k.GetSystemDirectoryW.argtypes, k.GetSystemDirectoryW.restype = [W.LPWSTR, W.UINT], W.UINT
    buf = C.create_unicode_buffer(32768)
    length = k.GetSystemDirectoryW(buf, len(buf))
    if not 0 < length < len(buf):
        raise SafetyError('无法确定受信任的 Windows 系统目录。')
    return str(Path(buf.value) / relative)


def windows_ps_env():
    # Python 子进程不会像 PowerShell 自己那样清理跨版本模块路径。
    env = os.environ.copy()
    env['PSModulePath'] = ';'.join([system_tool('WindowsPowerShell/v1.0/Modules'),
                                  str(helper_root().parent / 'WindowsPowerShell/Modules')])
    return env


# Get-Disk 同时提供系统/启动标记；Win32_DiskDrive 提供物理盘的 PnP ID。
# 不插入用户输入，不调用任何 Set-/Remove-/Dismount- 命令。
INVENTORY = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
$disks = @(Get-Disk)
$physical = @(Get-CimInstance Win32_DiskDrive)
$parts = @(Get-Partition)
$protected = @()
function Get-ProtectedDisk($path) {
    $volumes = @(Get-Volume -FilePath $path)
    if ($volumes.Count -ne 1) { throw 'Cannot resolve protected volume' }
    $mapped = @(Get-Partition -Volume $volumes[0])
    if ($mapped.Count -eq 0) { throw 'Cannot resolve protected disk' }
    $mapped | ForEach-Object DiskNumber
}
foreach ($p in @(Get-CimInstance Win32_PageFileUsage)) {
    # 使用路径解析，覆盖文件夹挂载点；无法解析时整个枚举失败。
    $protected += @(Get-ProtectedDisk $p.Name)
}
$protected += @(Get-ProtectedDisk (Join-Path $env:SystemRoot 'System32\ntdll.dll'))
if ($protected.Count -eq 0) { throw 'Cannot identify OS disk' }
$rows = @(foreach ($d in $disks) {
    $w = @($physical | Where-Object { $_.Index -eq $d.Number })
    if ($w.Count -ne 1) { throw 'Ambiguous physical disk mapping' }
    $pp = @($parts | Where-Object { $_.DiskNumber -eq $d.Number })
    [pscustomobject]@{
        number = [int]$d.Number; bus = [string]$d.BusType
        model = [string]$w[0].Model; size = [string]$d.Size
        serial = [string]$w[0].SerialNumber; unique = [string]$d.UniqueId
        pnp = [string]$w[0].PNPDeviceID
        boot = $d.IsBoot; system = $d.IsSystem; offline = $d.IsOffline
        protected = ($protected -contains $d.Number)
        partitions = @($pp | ForEach-Object {
            [pscustomobject]@{
                number = [int]$_.PartitionNumber
                gpt = [string]$_.GptType
                offset = [string]$_.Offset; size = [string]$_.Size
                boot = $_.IsBoot; system = $_.IsSystem
                paths = @($_.AccessPaths | Sort-Object)
            }
        })
    }
})
# 保留所有物理盘用于同一 USB 设备下的多 LUN 检查（包括动态磁盘）。
[pscustomobject]@{disks=$rows; physical=@($physical | ForEach-Object {
    [pscustomobject]@{number=[int]$_.Index; pnp=[string]$_.PNPDeviceID}
})} | ConvertTo-Json -Depth 8 -Compress
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""


def inventory():
    exe = system_tool('WindowsPowerShell/v1.0/powershell.exe')
    encoded = base64.b64encode(INVENTORY.encode('utf-16le')).decode('ascii')
    try:
        p = subprocess.run([exe, '-NoLogo', '-NoProfile', '-NonInteractive',
                            '-EncodedCommand', encoded], capture_output=True,
                           timeout=45, creationflags=subprocess.CREATE_NO_WINDOW, env=windows_ps_env())
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SafetyError(f'读取磁盘信息失败：{e}') from e
    if p.returncode:
        reason = p.stderr.decode('utf-8', errors='replace').strip()
        raise DeviceError('WMI/Storage 枚举失败：' + reason[:1200], '读取设备信息失败')
    try:
        return json.loads(p.stdout.decode('utf-8-sig'))
    except (ValueError, UnicodeError) as e:
        raise SafetyError('系统返回了无法解析的磁盘信息，已停止操作。') from e


VETO = ['原因未知', '旧设备不支持安全移除', '仍有关闭操作未完成',
        '应用程序拒绝移除', 'Windows 服务拒绝移除', '仍有打开的文件或设备句柄',
        '设备拒绝移除', '驱动程序拒绝移除', '设备不支持此请求', '电力不足',
        '设备不可禁用', '旧驱动不支持移除', '权限不足（可尝试以管理员身份运行）',
        '设备已被移除（本次不算退出成功）']


class Native:
    """所有 Win32 函数显式声明参数，避免 64 位句柄被截断。"""
    def __init__(self):
        if os.name != 'nt':
            raise SafetyError('仅支持 Windows 11。')
        self.cm = C.WinDLL('cfgmgr32', use_last_error=True)
        specs = {
            'CM_Locate_DevNodeW': [C.POINTER(W.DWORD), W.LPWSTR, W.ULONG],
            'CM_Get_Parent': [C.POINTER(W.DWORD), W.DWORD, W.ULONG],
            'CM_Get_Device_IDW': [W.DWORD, W.LPWSTR, W.ULONG, W.ULONG],
            'CM_Get_DevNode_Registry_PropertyW':
                [W.DWORD, W.ULONG, C.POINTER(W.ULONG), W.LPVOID,
                 C.POINTER(W.ULONG), W.ULONG],
            'CM_Request_Device_EjectW':
                [W.DWORD, C.POINTER(C.c_int), W.LPWSTR, W.ULONG, W.ULONG],
        }
        for name, args in specs.items():
            f = getattr(self.cm, name)
            f.argtypes, f.restype = args, W.ULONG
        self.io = VolumeIO()

    @staticmethod
    def check(cr):
        if cr != 0:
            raise SafetyError(f'设备信息查询失败，CONFIGRET=0x{cr:08X}；请刷新后重试。')

    def locate(self, instance):
        if not instance:
            raise SafetyError('设备实例 ID 为空，拒绝操作。')
        node = W.DWORD()
        self.check(self.cm.CM_Locate_DevNodeW(C.byref(node), instance, 0))
        return node.value

    def chain(self, instance):
        node = self.locate(instance)
        result = []
        for _ in range(64):
            buf = C.create_unicode_buffer(1024)
            self.check(self.cm.CM_Get_Device_IDW(node, buf, len(buf), 0))
            result.append((node, buf.value.upper()))
            if buf.value.upper().startswith('HTREE\\ROOT\\'):
                return result
            parent = W.DWORD()
            self.check(self.cm.CM_Get_Parent(C.byref(parent), node, 0))
            node = parent.value
        raise SafetyError('设备树异常，拒绝操作。')

    def prop(self, node, key, text=False):
        buf = C.create_unicode_buffer(1024) if text else W.DWORD()
        length, kind = W.ULONG(C.sizeof(buf)), W.ULONG()
        self.check(self.cm.CM_Get_DevNode_Registry_PropertyW(
            node, key, C.byref(kind), C.byref(buf), C.byref(length), 0))
        if kind.value != (1 if text else 4):  # REG_SZ / REG_DWORD
            raise SafetyError('设备属性类型异常，拒绝操作。')
        return buf.value

    def usb_target(self, instance):
        for node, name in self.chain(instance):
            if name.startswith('USB\\VID_'):
                # 只接受独立 USB 大容量存储设备，绝不上溯至 USB 集线器。
                if '&MI_' in name.split('\\')[1]:
                    raise SafetyError('不支持复合 USB 设备，无法保证只退出目标硬盘。')
                service = self.prop(node, 0x05, text=True).upper()  # CM_DRP_SERVICE
                caps = self.prop(node, 0x10)  # CM_DRP_CAPABILITIES
                if service not in ('USBSTOR', 'UASPSTOR') or not caps & 0x04:
                    raise SafetyError('未确认是可移除的独立 USB 存储设备，不支持安全退出。')
                return name
        raise SafetyError('没有找到可验证的 USB 存储设备实例。')

    def request_eject(self, instance):
        node = self.locate(instance)  # 不复用过期的 DEVINST
        veto, name = C.c_int(), C.create_unicode_buffer(260)
        cr = self.cm.CM_Request_Device_EjectW(node, C.byref(veto), name, len(name), 0)
        if cr:
            reason = VETO[veto.value] if 0 <= veto.value < len(VETO) else '未知否决类型'
            detail = f'；相关对象：{name.value}' if name.value else ''
            raise SafetyError(f'退出失败：{reason}{detail}；CONFIGRET=0x{cr:08X}。'
                              '请关闭占用程序后重试；程序不会强制卸载。')


class Extent(C.Structure):
    _fields_ = [('disk', W.DWORD), ('offset', C.c_longlong), ('length', C.c_longlong)]


class Extents(C.Structure):
    _fields_ = [('count', W.DWORD), ('items', Extent * 1)]


class VolumeIO:
    """句柄只在确认后的操作中打开；所有锁均由 finally 中关闭句柄释放。"""
    def __init__(self):
        self.k = C.WinDLL('kernel32', use_last_error=True)
        specs = {
            'CreateFileW': ([W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID,
                             W.DWORD, W.DWORD, W.HANDLE], W.HANDLE),
            'CloseHandle': ([W.HANDLE], W.BOOL),
            'FlushFileBuffers': ([W.HANDLE], W.BOOL),
            'DeviceIoControl': ([W.HANDLE, W.DWORD, W.LPVOID, W.DWORD,
                                 W.LPVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID], W.BOOL),
            'FindFirstVolumeW': ([W.LPWSTR, W.DWORD], W.HANDLE),
            'FindNextVolumeW': ([W.HANDLE, W.LPWSTR, W.DWORD], W.BOOL),
            'FindVolumeClose': ([W.HANDLE], W.BOOL),
            'GetDriveTypeW': ([W.LPCWSTR], W.UINT),
        }
        for name, (args, result) in specs.items():
            f = getattr(self.k, name)
            f.argtypes, f.restype = args, result

    @staticmethod
    def error(action, path='', access=None):
        code = C.get_last_error()
        if code in (32, 33):
            category = '硬盘被占用'
        elif code == 5 and action.startswith('锁卷'):
            category = '锁卷被拒绝（可能占用、过滤驱动或权限限制）'
        elif code in (5, 1314):
            category = '访问被拒绝（ACL、驱动策略或权限不足）'
        elif code in (1, 50):
            category = '协议或接口不支持'
        else:
            category = '操作失败'
        context = f'；路径={path}' if path else ''
        context += f'；请求访问=0x{access:08X}' if access is not None else ''
        return DeviceError(f'{action}：{C.FormatError(code).strip()} (WinError {code}){context}', category, code)

    def open(self, path, write=False):
        h = self.k.CreateFileW(path, 0xC0000000 if write else 0, 3, None, 3, 0, None)
        if h == C.c_void_p(-1).value:
            raise self.error('CreateFileW 打开设备/卷', path, 0xC0000000 if write else 0)
        return h

    def close(self, h):
        if not self.k.CloseHandle(h):
            raise self.error('关闭设备句柄')

    def ioctl(self, h, code, data=b'', size=65536):
        out, returned = C.create_string_buffer(size) if size else None, W.DWORD()
        inp = C.create_string_buffer(data) if data else None
        if not self.k.DeviceIoControl(h, code, inp, len(data), out, size,
                                      C.byref(returned), None):
            action = '锁卷 FSCTL_LOCK_VOLUME' if code == 0x90018 else f'DeviceIoControl 0x{code:X}'
            raise self.error(action)
        return out.raw[:returned.value] if out is not None else b''

    def verify_metadata(self, h, disk):
        raw = self.ioctl(h, 0x2D1080)  # IOCTL_STORAGE_GET_DEVICE_NUMBER
        if len(raw) < 12 or struct.unpack_from('<III', raw)[:2] != (7, disk.number):
            raise SafetyError('PhysicalDrive 路径与实际物理磁盘编号不一致。')
        desc = self.ioctl(h, 0x2D1400, struct.pack('<III', 0, 0, 0))
        if len(desc) < 36 or struct.unpack_from('<I', desc, 28)[0] != 7:
            raise SafetyError('原生存储描述符未报告 USB 总线，禁止操作。')

    def verify_disk(self, h, disk):
        self.verify_metadata(h, disk)
        length = self.ioctl(h, 0x7405C)  # IOCTL_DISK_GET_LENGTH_INFO, READ_ACCESS
        if len(length) < 8 or struct.unpack_from('<q', length)[0] != disk.size:
            raise SafetyError('原生磁盘容量与选择不一致。')

    def extent_numbers(self, h):
        raw = self.ioctl(h, 0x560000)  # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
        if len(raw) < Extents.items.offset:
            raise SafetyError('卷磁盘映射返回不完整。')
        count = struct.unpack_from('<I', raw)[0]
        start, stride = Extents.items.offset, C.sizeof(Extent)
        if not count or start + count * stride > len(raw):
            raise SafetyError('卷磁盘映射为空或不完整。')
        return [struct.unpack_from('<I', raw, start + i * stride)[0] for i in range(count)]

    def volume_paths(self, number):
        buf = C.create_unicode_buffer(1024)
        search = self.k.FindFirstVolumeW(buf, len(buf))
        if search == C.c_void_p(-1).value:
            raise self.error('枚举所有卷')
        paths = []
        try:
            while True:
                path = buf.value
                if self.k.GetDriveTypeW(path) != 5:  # 排除光驱；其余查询失败就停止。
                    h = self.open(path.rstrip('\\'))
                    try:
                        numbers = self.extent_numbers(h)
                        if number in numbers:
                            if numbers != [number]:
                                raise SafetyError('目标卷跨磁盘或含多个区段，禁止操作。')
                            paths.append(path)
                    finally:
                        self.close(h)
                if not self.k.FindNextVolumeW(search, buf, len(buf)):
                    if C.get_last_error() != 18:  # ERROR_NO_MORE_FILES
                        raise self.error('枚举卷')
                    break
        finally:
            self.k.FindVolumeClose(search)
        return sorted(paths)

    def flush(self, h):
        if not self.k.FlushFileBuffers(h):
            raise self.error('刷新缓存')

    def lock(self, h):
        self.ioctl(h, 0x90018, size=0)  # FSCTL_LOCK_VOLUME：有打开文件即失败，成功时再次刷新。

    def dismount(self, h):
        self.ioctl(h, 0x90020, size=0)  # 仅在目标所有卷均已成功锁定后调用。


@dataclass(frozen=True)
class Profile:
    model: str
    serial: str
    size: int
    rpm: int


class Smartctl:
    """固定 SAT 标准透传，不自动选择 JMicron 等厂商协议，不使用 shell。"""
    def __init__(self):
        if sys.argv[1:] == ['--helper-once']:
            self.exe = str(Path(__file__).resolve().parent / 'smartctl.exe')
            return
        candidates = [Path(os.environ.get('LOCALAPPDATA', '')) /
                      'Programs/SafeEjectTools/bin/smartctl.exe',
                      Path(os.environ.get('ProgramFiles', r'C:\Program Files')) /
                      'smartmontools/bin/smartctl.exe']
        self.exe = next((str(p) for p in candidates if p.is_file()), shutil.which('smartctl'))
        if not self.exe:
            raise SafetyError('缺少 smartctl >= 7.5。请安装 smartmontools 后重新运行。')

    def call(self, disk, options):
        if type(disk.number) is not int or not 0 <= disk.number <= 255:
            raise SafetyError('不支持的物理磁盘编号。')
        command = [self.exe, '-j', '-d', 'sat', *options, f'/dev/pd{disk.number}']
        try:
            p = subprocess.run(command, capture_output=True, timeout=45,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SafetyError(f'smartctl 未完成；命令执行状态未知：{e}') from e
        try:
            data = json.loads(p.stdout.decode('utf-8'))
        except (ValueError, UnicodeError) as e:
            raise SafetyError('smartctl 未返回有效 JSON，命令状态未知。') from e
        version = data.get('smartctl', {}).get('version', [])
        if version < [7, 5]:
            raise SafetyError('需要 smartctl 7.5 或更新版本。')
        return p.returncode, data

    @staticmethod
    def reason(data):
        return '；'.join(m.get('string', '') for m in
                        data.get('smartctl', {}).get('messages', []))[:700] or '桥接或命令不受支持'

    def identify(self, disk):
        code, data = self.call(disk, ['-i'])  # 仅 IDENTIFY/查询，不改 SMART 设置。
        device = data.get('device', {})
        if (code or device.get('protocol') != 'ATA' or device.get('type') != 'sat'
                or device.get('name') != f'/dev/pd{disk.number}'):
            reason = self.reason(data)
            if re.search(r'Error\s*=\s*5\b|access.*denied|permission denied', reason, re.I):
                raise DeviceError('smartctl SAT 打开设备被拒绝；与元数据枚举权限不同。' + reason,
                                  '权限不足或驱动访问限制', 5)
            raise DeviceError('标准 SAT 身份检测失败：' + reason, 'SAT 协议不支持或检测失败')
        profile = Profile(data.get('model_name', '').strip(),
                          data.get('serial_number', '').strip(),
                          data.get('user_capacity', {}).get('bytes', 0),
                          data.get('rotation_rate', 0))
        if (not profile.model or not profile.serial or profile.size != disk.size
                or type(profile.rpm) is not int or profile.rpm <= 0):
            raise SafetyError('未可靠识别有序列号的旋转机械硬盘，或 ATA 容量不匹配。')
        return profile

    def stop(self, disk):
        code, data = self.call(disk, ['-s', 'standby,now'])  # ATA STANDBY IMMEDIATE
        if code:
            reason = self.reason(data)
            category = ('硬盘盒不支持主动停转' if re.search(r'unsupported|not supported|illegal request', reason, re.I)
                        else '停转命令失败或状态未知')
            raise DeviceError(reason, category)

    def standby_report(self, disk):
        # CHECK POWER MODE 在 IDENTIFY 前执行；不附加 -i/-a 等唤醒性查询。
        code, data = self.call(disk, ['-n', 'standby,3,5'])
        power = data.get('power_mode', {})
        return code == 3 and power.get('ata_value') == 0 and power.get('name') == 'STANDBY'


@dataclass(frozen=True)
class Disk:
    number: int
    model: str
    size: int
    pnp: str
    usb: str
    serial: str
    unique: str
    partitions: str
    paths: tuple

    @property
    def caption(self):
        return f'磁盘 {self.number} · {self.model}'

    @property
    def device_path(self):
        return rf'\\.\PhysicalDrive{self.number}'

    @property
    def volumes(self):
        parts = json.loads(self.partitions)
        paths = {p for part in parts for p in part['paths']
                 if re.fullmatch(r'\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\', p)}
        return sorted(paths)

    @property
    def details(self):
        paths = '、'.join(self.paths) or '无盘符（可能有未挂载分区）'
        return (f'型号：{self.model}\n容量：{self.size / 10**9:.2f} GB '
                f'({self.size / 2**30:.2f} GiB)\n盘符/挂载点：{paths}')


def validate(row, physical, native):
    # 缺失的安全字段也不能被当作 False。
    for flag in ('boot', 'system', 'protected', 'offline'):
        if row.get(flag) is not False:
            raise SafetyError('系统/启动/分页文件磁盘、离线磁盘或状态不明，禁止退出。')
    if row.get('bus') != 'USB':
        raise SafetyError('不是 USB 总线磁盘。')
    parts = row['partitions']
    for part in parts:
        if part.get('boot') is not False or part.get('system') is not False:
            raise SafetyError('含系统/启动分区或分区状态不明，禁止退出。')
    pnp = row['pnp'].upper()
    if not pnp or int(row['size']) <= 0:
        raise SafetyError('磁盘身份或容量无法确认。')
    if not row['serial'].strip() and not row['unique'].strip():
        raise SafetyError('磁盘序列号和唯一 ID 均为空，无法可靠复核身份，禁止退出。')
    usb = native.usb_target(pnp)
    own = [p for p in physical if p['number'] == row['number']]
    if len(own) != 1 or own[0]['pnp'].upper() != pnp:
        raise SafetyError('物理磁盘编号与设备实例不一致。')
    # 一个 USB 设备若含多块盘，拒绝整设备退出，避免连带影响其他盘。
    for other in physical:
        if other['number'] != row['number']:
            if usb in [name for _, name in native.chain(other['pnp'])]:
                raise SafetyError('同一 USB 设备包含其他物理磁盘，不支持单独安全退出。')
    paths = tuple(sorted({p for part in parts for p in part['paths']
                          if not p.startswith('\\\\?\\Volume{')}))
    return Disk(row['number'], row['model'], int(row['size']), pnp, usb,
                row['serial'], row['unique'],
                json.dumps(parts, sort_keys=True), paths)


class Backend:
    def __init__(self, native=None, reader=inventory, smart=None):
        self.native = native if native is not None else Native()
        self.reader = reader
        self.smart = smart

    def scan(self):
        data = self.reader()
        disks, rejected = [], []
        for row in data['disks']:
            if row.get('bus') != 'USB':
                continue
            try:
                disks.append(validate(row, data['physical'], self.native))
            except SafetyError as e:
                rejected.append(f"磁盘 {row['number']}：{e}")
        return disks, rejected

    def revalidate(self, selected):
        disks, _ = self.scan()
        if selected not in disks:
            raise SafetyError('磁盘身份、分区或安全状态已变化；请刷新并重新确认。')

    def inspect(self, selected):
        """只读检测：不执行 flush、lock、dismount、stop 或 eject。"""
        self.revalidate(selected)
        if self.smart is None:
            self.smart = Smartctl()
        h = self.native.io.open(selected.device_path)  # 元数据查询不申请读写权限。
        try:
            self.native.io.verify_metadata(h, selected)
            profile = self.smart.identify(selected)
            self.revalidate(selected)
            return profile
        finally:
            self.native.io.close(h)

    def mapped_volumes(self, selected):
        expected = selected.volumes
        # 不猜测没有卷 GUID 的数据分区；仅 GPT MSR 可无文件系统卷。
        for part in json.loads(selected.partitions):
            if not any(p in expected for p in part['paths']):
                if part.get('gpt', '').strip('{}').upper() != 'E3C9E316-0B5C-4DB8-817D-F92DF00215AE':
                    raise SafetyError('存在无法映射至卷 GUID 的分区，不支持本次停转。')
        actual = self.native.io.volume_paths(selected.number)
        if not expected or sorted(p.casefold() for p in expected) != sorted(p.casefold() for p in actual):
            raise SafetyError('卷 GUID 与全部物理磁盘范围映射不一致或为空。')
        return expected

    def eject(self, selected, profile=None, confirmed=False, progress=lambda text: None):
        if not confirmed or profile is None:
            raise SafetyError('必须先完成只读检测并在窗口中明确确认。')
        # 所有会读取身份/容量/卷列表的操作均在停转前完成。
        if self.inspect(selected) != profile:
            raise SafetyError('ATA 型号、序列号、容量或转速已变化，请重新检测。')
        paths = self.mapped_volumes(selected)
        io, handles, disk_handle = self.native.io, [], None
        stopped, standby, stop_error = False, False, ''
        close_errors = []
        try:
            disk_handle = io.open(selected.device_path, write=True)
            io.verify_disk(disk_handle, selected)
            for path in paths:
                h = io.open(path.rstrip('\\'), write=True)
                handles.append(h)
                if io.extent_numbers(h) != [selected.number]:
                    raise SafetyError('卷映射已变化，拒绝操作。')
            progress('正在刷新缓存')
            for h in handles:
                io.flush(h)
            progress('正在解除磁盘占用')
            for h in handles:
                io.lock(h)  # 任一失败即退出；不强制关闭其他程序。
            # 全部卷锁到手后，再校验一次物理盘和 ATA 身份。
            io.verify_disk(disk_handle, selected)
            if (self.native.usb_target(selected.pnp) != selected.usb
                    or any(io.extent_numbers(h) != [selected.number] for h in handles)
                    or self.smart.identify(selected) != profile):
                raise SafetyError('锁卷期间设备身份或卷拓扑变化。')
            for h in handles:
                io.dismount(h)
            progress('正在请求机械硬盘停转')
            try:
                self.smart.stop(selected)
                stopped = True
                standby = self.smart.standby_report(selected)
            except SafetyError as e:
                stop_error = str(e)
        finally:
            # 自有句柄会阻止 QUERY_REMOVE；全部关闭后才请求 PnP，不再扫描设备。
            for h in reversed(handles + ([disk_handle] if disk_handle is not None else [])):
                try:
                    io.close(h)
                except SafetyError as e:
                    close_errors.append(str(e))
            if close_errors:
                raise SafetyError('句柄清理失败，未请求 PnP 移除；请勿断电。' + '；'.join(close_errors))
        progress('正在安全移除 USB 设备')
        try:
            self.native.request_eject(selected.usb)
        except SafetyError as e:
            raise SafetyError(f'操作失败：未完成 Windows 安全移除，请勿断电。{e}\n'
                              '卷锁已释放，正常访问可能重新唤醒硬盘；刷新后重试。') from e
        command = '停转命令已完成，但物理停转未确认' if stopped else '主动停转请求失败或状态未知'
        report = '移除前硬盘曾报告 STANDBY' if standby else '未确认硬盘报告待机'
        return ('安全移除成功：Windows 已完成设备安全移除；机械停转状态未知。\n'
                f'{command}；{report}。\n'
                + (f'停转检测详情：{stop_error}\n' if stop_error else '')
                + '可关闭硬盘盒电源，等待完全停转后再换盘。')


TASK_NAME = 'UsbSafeEject-Authorized'
RUNTIME_HASH = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'
SMART_HASH = 'b5db94e5082c042be44994b7a4fa8f7b5c8e713b2ab1c9a560d8f7a7995ea27d'
HELPER_VERSION = 2  # v2 收紧 request.json ACL；受保护操作/协议变化必须递增。


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def powershell(script, timeout=60):
    exe = system_tool('WindowsPowerShell/v1.0/powershell.exe')
    wrapper = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
               "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); try { "
               + script + " } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
    encoded = base64.b64encode(wrapper.encode('utf-16le')).decode()
    p = subprocess.run([exe, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                       capture_output=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW,
                       env=windows_ps_env())
    if p.returncode:
        raise DeviceError(p.stderr.decode('utf-8', errors='replace')[:1200], '授权助手不可用')
    return p.stdout.decode('utf-8-sig', errors='replace').strip()


def user_sid():
    sid = powershell('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value')
    if not re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+', sid):
        raise SafetyError('当前账户 SID 不受支持。')
    return sid


def helper_root():
    # 使用受保护的 HKLM 值，不信任调用者的 ProgramFiles 环境变量。
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion',
                        0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        return Path(winreg.QueryValueEx(key, 'ProgramFilesDir')[0]) / 'UsbSafeEject'


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_ipc_acl(entries, expected_sid, inheritance_disabled, required_rights, allow_legacy=False):
    """Only SYSTEM, Administrators, and the authorized SID may access an IPC file."""
    if entries is None and allow_legacy:
        entries = []
    if not isinstance(entries, list):
        raise SafetyError('授权助手 IPC 文件 ACL 格式错误。')
    if not inheritance_disabled and not allow_legacy:
        raise SafetyError('IPC 文件仍继承目录权限。')
    seen_authorized_sid = False
    protected_sids = {'S-1-5-18', 'S-1-5-32-544'}
    forbidden_user_rights = 0x100D0040  # DELETE, WRITE_DAC, WRITE_OWNER, DELETE_CHILD, GENERIC_ALL
    unprivileged_write_rights = 0x500D0156
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'sid', 'type', 'rights'}:
            raise SafetyError('授权助手 IPC 文件 ACL 条目格式错误。')
        sid, ace_type, rights = entry['sid'], entry['type'], entry['rights']
        if not isinstance(sid, str) or ace_type != 'Allow' or type(rights) is not int:
            raise SafetyError('授权助手 IPC 文件存在未预期的 ACL 项。')
        if sid in protected_sids:
            continue
        if sid == expected_sid:
            if rights & forbidden_user_rights or rights & required_rights != required_rights:
                raise SafetyError('授权账户的 IPC 文件权限过宽或不足。')
            seen_authorized_sid = True
            continue
        # Only an administrator-run upgrade may tolerate old read-only inherited ACEs.
        if allow_legacy and rights & unprivileged_write_rights == 0:
            continue
        raise SafetyError('IPC 文件向其他账户或用户组开放了读取/写入权限。')
    if not seen_authorized_sid and not allow_legacy:
        raise SafetyError('IPC 文件缺少当前授权账户的所需权限。')


def validate_request_acl(entries, expected_sid, inheritance_disabled, allow_legacy=False):
    return validate_ipc_acl(entries, expected_sid, inheritance_disabled, 0x3, allow_legacy)


def validate_reply_acl(entries, expected_sid, inheritance_disabled, allow_legacy=False):
    return validate_ipc_acl(entries, expected_sid, inheritance_disabled, 0x1, allow_legacy)


def request_acl_icacls_args(path, sid):
    """Return the exact ACL reset for the pre-created IPC request file."""
    return ipc_acl_icacls_args(path, sid, 'R,W')


def reply_acl_icacls_args(path, sid):
    """Return the exact ACL reset for result files that may contain disk identity."""
    return ipc_acl_icacls_args(path, sid, 'R')


def ipc_acl_icacls_args(path, sid, rights):
    return (str(path), '/inheritance:r', '/grant:r',
            '*S-1-5-18:(F)', '*S-1-5-32-544:(F)', f'*{sid}:({rights})')


def set_ipc_file_acl(path, sid, rights):
    exe = system_tool('icacls.exe')
    p = subprocess.run([exe, *ipc_acl_icacls_args(path, sid, rights)],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if p.returncode:
        raise SafetyError('无法限制授权助手 IPC 文件的读取权限。')


def validate_request(data, previous_nonce=None):
    keys = {'version', 'nonce', 'time', 'action', 'disk', 'profile'}
    if not isinstance(data, dict) or set(data) != keys:
        raise SafetyError('拒绝未知或不完整的助手请求字段。')
    if (type(data['version']) is not int or data['version'] != HELPER_VERSION
            or data['action'] not in ('health', 'inspect', 'eject')
            or not isinstance(data['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', data['nonce'])
            or data['nonce'] == previous_nonce or type(data['time']) not in (int, float)
            or not 0 <= time.time() - data['time'] <= 60):
        raise SafetyError('拒绝无效、重复或过期的请求。')
    if data['action'] == 'health':
        if data['disk'] is not None or data['profile'] is not None:
            raise SafetyError('健康检查不能带设备参数。')
        return None, None
    raw = data['disk']
    if not isinstance(raw, dict) or set(raw) != set(Disk.__dataclass_fields__):
        raise SafetyError('设备身份请求结构不正确。')
    if (type(raw['number']) is not int or not 0 <= raw['number'] <= 255
            or type(raw['size']) is not int or raw['size'] <= 0
            or not isinstance(raw['paths'], list)
            or any(not isinstance(raw[k], str) or len(raw[k]) > 32000
                   for k in ('model', 'pnp', 'usb', 'serial', 'unique', 'partitions'))
            or any(not isinstance(p, str) or len(p) > 1024 for p in raw['paths'])):
        raise SafetyError('设备身份请求类型或长度不正确。')
    disk = Disk(**dict(raw, paths=tuple(raw['paths'])))
    profile = None
    if data['action'] == 'eject':
        raw_profile = data['profile']
        if not isinstance(raw_profile, dict) or set(raw_profile) != set(Profile.__dataclass_fields__):
            raise SafetyError('缺少已确认的 ATA 身份。')
        profile = Profile(**raw_profile)
        if (not isinstance(profile.model, str) or not isinstance(profile.serial, str)
                or not profile.model or not profile.serial or len(profile.model) > 256
                or len(profile.serial) > 256 or type(profile.size) is not int
                or profile.size != disk.size or type(profile.rpm) is not int or profile.rpm <= 0):
            raise SafetyError('ATA 身份类型不正确。')
    elif data['profile'] is not None:
        raise SafetyError('只读检测不能带控制参数。')
    return disk, profile


def verify_installation(root, allow_incomplete=False, sid=None):
    """递归检查所有者/DACL/重解析点；不能用 Program Files 路径名代替 ACL。"""
    if allow_incomplete and not admin():
        raise SafetyError('修复安装只允许管理员执行。')
    config_path = root / 'config.json'
    config = (json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists()
              else {'sid': sid})
    expected_sid = config.get('sid')
    if not isinstance(expected_sid, str) or not re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+', expected_sid):
        raise SafetyError('授权配置缺失或账户不正确。')
    legacy_ipc_acl = allow_incomplete and admin()
    legacy_ipc_acl_ps = '$true' if legacy_ipc_acl else '$false'
    acl_report = powershell(f"""
$root={ps_quote(root)};
$ipcPaths=@((Join-Path $root 'request.json'),(Join-Path $root 'reply.json'),(Join-Path $root 'reply.tmp'));
$items=@(Get-Item -LiteralPath $root -Force)+@(Get-ChildItem -LiteralPath $root -Recurse -Force);
foreach($f in $items) {{
 if($f.Attributes -band [IO.FileAttributes]::ReparsePoint) {{throw 'Reparse point rejected'}};
 $a=Get-Acl -LiteralPath $f.FullName;
 $owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;
 if($owner -notin @('S-1-5-18','S-1-5-32-544')) {{throw 'Unsafe owner'}};
 if($ipcPaths -contains $f.FullName) {{continue}};
 foreach($r in $a.Access) {{
  if($r.AccessControlType -ne 'Allow') {{continue}};
  $sid=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;
  if($sid -in @('S-1-5-18','S-1-5-32-544')) {{continue}};
  $bits=[int64]$r.FileSystemRights;
  if($bits -band 0x500D0156L) {{throw 'Unprivileged write permission'}}
 }}
}}
$ipcReports=@{{}};
foreach($name in @('request.json','reply.json','reply.tmp')) {{
 $path=Join-Path $root $name;
 if(Test-Path -LiteralPath $path) {{
   $fileAcl=Get-Acl -LiteralPath $path;
   $entries=@($fileAcl.Access | ForEach-Object {{
     [pscustomobject]@{{
       sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;
       type=$_.AccessControlType.ToString(); rights=[int64]$_.FileSystemRights
     }}
   }});
   $ipcReports[$name]=[pscustomobject]@{{protected=[bool]$fileAcl.AreAccessRulesProtected; entries=$entries}};
 }} else {{$ipcReports[$name]=$null}}
}}
[pscustomobject]@{{ipc=$ipcReports}} |
 ConvertTo-Json -Depth 4 -Compress
""")
    try:
        acl_data = json.loads(acl_report)
    except (TypeError, ValueError) as e:
        raise SafetyError('授权助手请求文件 ACL 检查结果无效。') from e
    if not isinstance(acl_data, dict) or not isinstance(acl_data.get('ipc'), dict):
        raise SafetyError('授权助手 IPC ACL 检查结果无效。')
    for name, required, optional in (('request.json', 0x3, False),
                                     ('reply.json', 0x1, False),
                                     ('reply.tmp', 0x1, True)):
        report = acl_data['ipc'].get(name)
        if report is None:
            if optional or legacy_ipc_acl:
                continue
            raise SafetyError('授权助手 IPC 文件缺失。')
        if not isinstance(report, dict):
            raise SafetyError('授权助手 IPC ACL 条目无效。')
        validate_ipc_acl(report.get('entries'), expected_sid,
                         report.get('protected') is True, required,
                         allow_legacy=legacy_ipc_acl)
    if allow_incomplete:
        return config
    if config.get('version') != HELPER_VERSION:
        raise SafetyError('授权助手版本不匹配，请重新授权更新。')
    for name, digest in config['hashes'].items():
        path = root / name
        if path.resolve().parent != root.resolve() or file_hash(path) != digest:
            raise SafetyError('受保护运行文件完整性检查失败。')
    return config


def read_fixed_request(root):
    io = VolumeIO()
    path = str(root / 'request.json')
    h = io.k.CreateFileW(path, 0x80000000, 1, None, 3, 0x00200000, None)
    if h == C.c_void_p(-1).value:
        raise io.error('读取固定请求快照', path)
    try:
        info = (W.DWORD * 2)()
        query = io.k.GetFileInformationByHandleEx
        query.argtypes, query.restype = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD], W.BOOL
        if not query(h, 9, info, C.sizeof(info)) or info[0] & 0x400:
            raise SafetyError('请求文件重解析点或属性检查失败。')
        read = io.k.ReadFile
        read.argtypes, read.restype = [W.HANDLE, W.LPVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID], W.BOOL
        buf, size = C.create_string_buffer(65537), W.DWORD()
        if not read(h, buf, len(buf), C.byref(size), None) or size.value > 65536:
            raise SafetyError('请求读取失败或超过大小限制。')
        return json.loads(buf.raw[:size.value].decode('utf-8'))
    finally:
        io.close(h)


def write_reply(root, data, sid):
    temp = root / 'reply.tmp'
    if not temp.exists():
        with temp.open('xb'):
            pass
    set_ipc_file_acl(temp, sid, 'R')
    temp.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    for attempt in range(20):
        try:
            temp.replace(root / 'reply.json')
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


def helper_once():
    root = helper_root()
    if not admin() or Path(__file__).resolve() != root / 'safe_eject.py':
        raise SafetyError('辅助入口仅允许受保护的已授权副本运行。')
    config = verify_installation(root)
    if not config.get('installed'):
        raise SafetyError('授权配置尚未完成。')
    previous = json.loads((root / 'reply.json').read_text(encoding='utf-8')).get('nonce')
    request = read_fixed_request(root)
    disk, profile = validate_request(request, previous)
    nonce = request['nonce']
    def send(state, value):
        write_reply(root, {'nonce': nonce, 'state': state, 'value': value}, config['sid'])
    send('progress', '授权助手已校验请求')
    try:
        if request['action'] == 'health':
            value = '授权助手可用'
        else:
            backend = Backend()
            if request['action'] == 'inspect':
                value = asdict(backend.inspect(disk))
            else:
                # SYSTEM 非交互调用仅启用其令牌已有的权限，不修改全局策略。
                enable_load_privilege()
                value = backend.eject(disk, profile, confirmed=True,
                                      progress=lambda text: send('progress', text))
        send('result', value)
    except Exception as e:
        send('error', str(e))


def enable_load_privilege():
    # 用系统 PowerShell 不会改变父进程令牌，因此必须在当前 helper 令牌调用。
    class Luid(C.Structure):
        _fields_ = [('low', W.DWORD), ('high', W.LONG)]
    class Privilege(C.Structure):
        _fields_ = [('count', W.DWORD), ('luid', Luid), ('attributes', W.DWORD)]
    adv, k = C.WinDLL('advapi32', use_last_error=True), C.WinDLL('kernel32', use_last_error=True)
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    adv.LookupPrivilegeValueW.argtypes = [W.LPCWSTR, W.LPCWSTR, C.POINTER(Luid)]
    adv.AdjustTokenPrivileges.argtypes = [W.HANDLE, W.BOOL, C.POINTER(Privilege), W.DWORD, W.LPVOID, W.LPVOID]
    k.GetCurrentProcess.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    token, privilege = W.HANDLE(), Privilege(count=1, attributes=2)
    if not adv.OpenProcessToken(k.GetCurrentProcess(), 0x28, C.byref(token)):
        raise SafetyError('权限不足：无法检查辅助进程令牌。')
    try:
        if not adv.LookupPrivilegeValueW(None, 'SeLoadDriverPrivilege', C.byref(privilege.luid)):
            raise SafetyError('权限不足：令牌权限查询失败。')
        C.set_last_error(0)
        if not adv.AdjustTokenPrivileges(token, False, C.byref(privilege), 0, None, None) or C.get_last_error():
            raise SafetyError('权限不足：令牌没有可启用的 SeLoadDriverPrivilege。')
    finally:
        k.CloseHandle(token)


def protect_new_file_owners():
    """安装期间新建文件直接由 Administrators 所有，避免事后改所有者的窗口。"""
    adv, k = C.WinDLL('advapi32', use_last_error=True), C.WinDLL('kernel32', use_last_error=True)
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    adv.ConvertStringSidToSidW.argtypes = [W.LPCWSTR, C.POINTER(W.LPVOID)]
    adv.SetTokenInformation.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD]
    k.GetCurrentProcess.restype = W.HANDLE
    k.CloseHandle.argtypes, k.LocalFree.argtypes = [W.HANDLE], [W.LPVOID]
    token, owner = W.HANDLE(), W.LPVOID()
    if not adv.OpenProcessToken(k.GetCurrentProcess(), 0x88, C.byref(token)):
        raise SafetyError('无法设置安装文件所有者，拒绝继续安装。')
    try:
        if not adv.ConvertStringSidToSidW('S-1-5-32-544', C.byref(owner)):
            raise SafetyError('管理员组 SID 解析失败。')
        if not adv.SetTokenInformation(token, 4, C.byref(owner), C.sizeof(owner)):
            raise SafetyError('无法保护新文件的默认所有者，拒绝继续安装。')
    finally:
        if owner:
            k.LocalFree(owner)
        k.CloseHandle(token)


def install_helper(sid):
    if not admin() or not re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+', sid):
        raise SafetyError('首次初始化需要用户在 Windows UAC 中授权。')
    protect_new_file_owners()
    root = helper_root()
    if root.exists():
        # 拒绝接管未知目录；已安装副本升级也需要管理员重新校验。
        existing = verify_installation(root, allow_incomplete=True, sid=sid)
        if existing.get('sid') != sid:
            raise SafetyError('此助手已经授权其他账户，不能覆盖其授权。')
        state = powershell(f"$s=New-Object -ComObject Schedule.Service; $s.Connect(); "
                           f"try {{$s.GetFolder('\\').GetTask({ps_quote(TASK_NAME)}).State}} catch {{'absent'}}")
        if state in ('2', '4'):
            raise SafetyError('助手正在处理操作，禁止在此时更新。')
    else:
        root.mkdir()
    if any(os.lstat(p).st_file_attributes & 0x400 for p in [root, *root.parents]):
        raise SafetyError('安装路径含重解析点，拒绝安装。')
    def icacls(*args):
        exe = system_tool('icacls.exe')
        p = subprocess.run([exe, *map(str, args)], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if p.returncode:
            raise SafetyError('无法保护安装文件 ACL，未完成初始化。')
    icacls(root, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F',
           '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')
    icacls(root, '/setowner', '*S-1-5-32-544', '/T')
    # Hide any prior IPC data before replacing helper code; old replies may include ATA serials.
    for name, rights in (('request.json', 'R,W'), ('reply.json', 'R')):
        path = root / name
        if path.is_file():
            icacls(*ipc_acl_icacls_args(path, sid, rights))
    stale_reply = root / 'reply.tmp'
    if stale_reply.exists():
        stale_reply.unlink()
    archive = root / 'runtime.zip'
    urllib.request.urlretrieve('https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip', archive)
    if file_hash(archive) != RUNTIME_HASH:
        raise SafetyError('Python 官方运行包 SHA256 不匹配。')
    with zipfile.ZipFile(archive) as package:
        if any(Path(name).name != name or '..' in name for name in package.namelist()):
            raise SafetyError('运行包路径检查失败。')
        package.extractall(root)
    archive.unlink()
    smart = Path(Smartctl().exe)
    if file_hash(smart) != SMART_HASH:
        raise SafetyError('smartctl 与已核验的官方 7.5 版本不匹配，拒绝安装。')
    shutil.copyfile(smart, root / 'smartctl.exe')
    shutil.copyfile(Path(__file__), root / 'safe_eject.py')
    (root / 'python314._pth').write_text('python314.zip\n.\n', encoding='ascii')
    (root / 'request.json').write_text('{}', encoding='utf-8')
    (root / 'reply.json').write_text('{}', encoding='utf-8')
    icacls(*request_acl_icacls_args(root / 'request.json', sid))
    icacls(*reply_acl_icacls_args(root / 'reply.json', sid))
    hashes = {p.name: file_hash(p) for p in root.iterdir() if p.is_file()
              and p.name not in ('config.json', 'request.json', 'reply.json', 'reply.tmp')}
    config = {'version': HELPER_VERSION, 'sid': sid, 'hashes': hashes, 'installed': False}
    (root / 'config.json').write_text(json.dumps(config), encoding='utf-8')
    icacls(root, '/setowner', '*S-1-5-32-544', '/T')
    # IPC result files may contain ATA serials; they are readable only by this SID.
    icacls(*request_acl_icacls_args(root / 'request.json', sid))
    icacls(*reply_acl_icacls_args(root / 'reply.json', sid))
    verify_installation(root)
    sddl = f'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;{sid})'
    powershell(f"""
$s=New-Object -ComObject Schedule.Service; $s.Connect(); $f=$s.GetFolder('\\');
$t=$s.NewTask(0); $t.RegistrationInfo.Description='受限 USB 机械硬盘检测和安全退出助手';
$t.Principal.UserId='SYSTEM'; $t.Principal.LogonType=5; $t.Principal.RunLevel=1;
$t.Settings.MultipleInstances=2; $t.Settings.ExecutionTimeLimit='PT0S';
$t.Settings.DisallowStartIfOnBatteries=$false; $t.Settings.StopIfGoingOnBatteries=$false;
$t.Settings.AllowDemandStart=$true; $t.Settings.Enabled=$true;
$a=$t.Actions.Create(0); $a.Path={ps_quote(root / 'python.exe')};
$a.Arguments={ps_quote('-I -S "' + str(root / 'safe_eject.py') + '" --helper-once')};
$a.WorkingDirectory={ps_quote(root)};
$task=$f.RegisterTaskDefinition({ps_quote(TASK_NAME)},$t,6,'SYSTEM',$null,5,{ps_quote(sddl)});
$task.SetSecurityDescriptor({ps_quote(sddl)},0);
if($task.Definition.Actions.Count -ne 1 -or $task.Definition.Actions.Item(1).Path -ne $a.Path -or
 $task.Definition.Actions.Item(1).Arguments -ne $a.Arguments) {{throw 'Task action verification failed'}};
$sd=[Security.AccessControl.RawSecurityDescriptor]::new($task.GetSecurityDescriptor(7));
if($sd.Owner.Value -ne 'S-1-5-32-544') {{throw 'Unexpected task owner'}};
$seen=$false;
foreach($ace in $sd.DiscretionaryAcl) {{
 $id=$ace.SecurityIdentifier.Value;
 if($id -in @('S-1-5-18','S-1-5-32-544')) {{continue}};
 if($id -ne {ps_quote(sid)} -or $ace.AceType -ne 'AccessAllowed') {{throw 'Unexpected task ACE'}};
 if(([int64]$ace.AccessMask -band 0x500D0156L) -ne 0) {{throw 'Task grants excess permission'}};
 $seen=$true;
}}
if(-not $seen) {{throw 'Missing execute authorization'}};
""")
    config['installed'] = True
    (root / 'config.json').write_text(json.dumps(config), encoding='utf-8')


class HelperClient:
    def ready(self):
        try:
            config = json.loads((helper_root() / 'config.json').read_text(encoding='utf-8'))
            return (config.get('installed') is True and config.get('version') == HELPER_VERSION
                    and config.get('sid') == user_sid())
        except (OSError, ValueError, SafetyError):
            return False

    def initialize(self):
        sid = user_sid()
        args = subprocess.list2cmdline(['-I', str(Path(__file__).resolve()), '--install-helper', sid])
        try:
            powershell(f"$p=Start-Process -FilePath {ps_quote(sys.executable)} -ArgumentList {ps_quote(args)} "
                       "-Verb RunAs -WindowStyle Hidden -PassThru -Wait; if($p.ExitCode -ne 0){throw 'Initialization failed'}", 300)
        except (SafetyError, subprocess.TimeoutExpired) as e:
            raise DeviceError('Windows 授权被取消或初始化失败；普通 GUI 仍可读取设备信息。' + str(e), '权限提升失败') from e
        if not self.ready():
            raise SafetyError('初始化未完成，授权助手不可用。')
        self.call('health')  # 只检查授权通道，不访问磁盘。

    def call(self, action, disk=None, profile=None, progress=lambda text: None):
        with helper_mutex():
            return self._call(action, disk, profile, progress)

    def _call(self, action, disk=None, profile=None, progress=lambda text: None):
        root = helper_root()
        config = verify_installation(root)
        if not config.get('installed') or config['sid'] != user_sid():
            raise SafetyError('权限不足：此助手未授权当前账户。')
        # 数据协议不含可执行路径、命令行或任意输出文件名。
        request = {'version': HELPER_VERSION, 'nonce': uuid.uuid4().hex, 'time': time.time(),
                   'action': action, 'disk': asdict(disk) if disk else None,
                   'profile': asdict(profile) if profile else None}
        request = json.loads(json.dumps(request))
        validate_request(request)
        state = powershell(f"$s=New-Object -ComObject Schedule.Service; $s.Connect(); "
                           f"$s.GetFolder('\\').GetTask({ps_quote(TASK_NAME)}).State")
        if state in ('2', '4'):
            raise SafetyError('上一次助手任务仍在运行，请勿断电，等待其完成。')
        # 固定文件已由管理员创建，普通进程不能创建/替换目录或其他文件。
        (root / 'request.json').write_text(json.dumps(request), encoding='utf-8')
        powershell(f"$s=New-Object -ComObject Schedule.Service; $s.Connect(); "
                   f"$null=$s.GetFolder('\\').GetTask({ps_quote(TASK_NAME)}).Run($null)")
        deadline, last = time.monotonic() + 300, ''
        while time.monotonic() < deadline:
            try:
                reply = json.loads((root / 'reply.json').read_text(encoding='utf-8'))
            except (OSError, ValueError):
                reply = {}
            if reply.get('nonce') == request['nonce']:
                if reply.get('state') == 'error':
                    raise SafetyError(reply['value'])
                if reply.get('state') == 'result':
                    return reply['value']
                if reply.get('value') != last:
                    last = reply.get('value', '')
                    progress(last)
            time.sleep(0.15)
        raise SafetyError('助手结果等待超时，执行状态未知，请勿断电；不要重复提交操作。')


@contextmanager
def helper_mutex():
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateMutexW.argtypes, k.CreateMutexW.restype = [W.LPVOID, W.BOOL, W.LPCWSTR], W.HANDLE
    k.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    k.ReleaseMutex.argtypes = [W.HANDLE]
    k.CloseHandle.argtypes = [W.HANDLE]
    handle = k.CreateMutexW(None, False, 'Global\\UsbSafeEjectClient-' + user_sid())
    if not handle:
        raise SafetyError('无法取得操作互斥锁。')
    held = False
    try:
        if k.WaitForSingleObject(handle, 0) not in (0, 0x80):
            raise SafetyError('另一个窗口正在处理操作，请勿重复提交。')
        held = True
        yield
    finally:
        if held:
            k.ReleaseMutex(handle)
        k.CloseHandle(handle)


def main(auto_confirm=True):
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title('USB 硬盘安全退出')
    root.geometry('420x300')
    root.minsize(420, 300)
    frame = ttk.Frame(root, padding=12)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text='选择 USB 物理磁盘').pack(anchor='w')
    combo = ttk.Combobox(frame, state='readonly')
    combo.pack(fill='x', pady=(4, 8))
    info = tk.StringVar(value='正在读取设备…')
    ttk.Label(frame, textvariable=info, wraplength=390).pack(anchor='w')
    ttk.Label(frame, text='机械停转状态未知', foreground='#666666').pack(anchor='w', pady=4)
    buttons = ttk.Frame(frame)
    buttons.pack(pady=6)
    refresh = ttk.Button(buttons, text='刷新设备')
    eject = ttk.Button(buttons, text='安全退出并停转')
    refresh.pack(side='left', padx=8)
    eject.pack(side='left', padx=8)
    result = tk.StringVar(value='')
    ttk.Label(frame, textvariable=result, wraplength=390).pack(anchor='w')
    backend = Backend()
    helper = HelperClient()
    disks, busy, events, detected = [], False, queue.Queue(), {}

    def selection(event=None):
        i = combo.current()
        info.set(disks[i].details if 0 <= i < len(disks) else '没有可安全退出的 USB 磁盘')
        eject.configure(state='normal' if disks and not busy else 'disabled')

    def run(job, done):
        nonlocal busy
        busy = True
        refresh.configure(state='disabled')
        eject.configure(state='disabled')
        combo.configure(state='disabled')

        def worker():
            try:
                events.put((done, job(), None))
            except Exception as e:
                events.put((done, None, str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def poll():
        nonlocal busy
        try:
            done, value, error = events.get_nowait()
        except queue.Empty:
            pass
        else:
            if done is None:  # 工作线程只向队列发送状态，不操作 tkinter。
                result.set(value)
                root.after(100, poll)
                return
            busy = False
            refresh.configure(state='normal')
            combo.configure(state='readonly')
            if error:
                detected.clear()
                result.set(error[:110] + '\n未确认安全移除，请勿断电。')
                messagebox.showerror('操作未完成', error + '\n未确认安全移除，请勿断电。', parent=root)
            else:
                done(value)
            selection()
        root.after(100, poll)

    def scanned(value):
        nonlocal disks
        disks, rejected = value
        combo['values'] = [d.caption for d in disks]
        combo.set('')
        if disks:
            combo.current(0)
        result.set(f'找到 {len(disks)} 个可操作 USB 磁盘。'
                   + ('部分设备已拒绝，详见提示。' if rejected else ''))
        if rejected:
            messagebox.showwarning('以下 USB 磁盘不能退出', '\n'.join(rejected), parent=root)

    def refresh_list():
        detected.clear()
        result.set('正在读取设备…')
        run(backend.scan, scanned)

    def ejected(message):
        nonlocal disks
        disks = []
        combo['values'] = []
        combo.set('')
        result.set(message)
        messagebox.showinfo('安全移除完成', message, parent=root)

    def inspected(disk, profile):
        detected[disk] = profile
        result.set('只读检测完成：SAT 身份通路可用；停转支持未验证。再次点击按钮才能确认操作。')
        if auto_confirm:
            do_eject()
            return
        messagebox.showinfo('仅完成只读检测',
            f'{disk.device_path}\nATA 型号：{profile.model}\n转速：{profile.rpm} RPM\n'
            '已读取身份，尚未验证停转命令支持。\n没有刷新、锁卷、卸载、停转或弹出设备。'
            '\n再次点击按钮可确认实际操作。', parent=root)

    def do_eject():
        i = combo.current()
        if busy or not 0 <= i < len(disks):
            return
        disk = disks[i]
        if disk not in detected:
            initialize = False
            if not admin() and not helper.ready():
                initialize = messagebox.askyesno('一次性授权配置',
                    '主动停转和锁卷需要受限的特权助手。\n'
                    '将安装受保护的 Python/脚本/smartctl，并注册固定的按需计划任务。\n'
                    '只授权当前账户调用 USB 硬盘检测及安全退出操作；不会修改 UAC 或系统安全策略。\n'
                    '同一账户的其他程序也能调用这些固定操作，助手仍强制核验磁盘身份。\n'
                    '仅这次会显示 Windows 管理员授权窗口。现在初始化？', parent=root, default='no')
                if not initialize:
                    result.set('权限不足：尚未配置授权助手；普通设备枚举可用。')
                    return
            result.set('正在进行只读身份和 SAT 通路检测（可能唤醒休眠盘）…')
            def inspect_job():
                if initialize:
                    helper.initialize()
                return backend.inspect(disk) if admin() else Profile(**helper.call('inspect', disk))
            run(inspect_job, lambda p: inspected(disk, p))
            return
        profile = detected[disk]
        if messagebox.askyesno('确认安全退出',
                f'{disk.caption}\n{disk.device_path}\nATA 型号：{profile.model}\n'
                f'\n将刷新并锁定所有卷，带锁卸载、请求标准停转，再请求 PnP 安全移除。'
                '\n停转失败时仍尝试安全移除；无法保证 PnP 不会重新唤醒硬盘。'
                '\n请先保存文件并关闭使用该盘的程序。'
                '\n确认及处理期间请勿插拔或更换硬盘。'
                '\n已核对这是你的外置 USB 硬盘盒，确认退出？', parent=root, default='no'):
            result.set('Windows 正在处理安全移除请求，请勿断电…')
            progress = lambda text: events.put((None, text, None))
            run(lambda: backend.eject(disk, profile, confirmed=True, progress=progress)
                if admin() else helper.call('eject', disk, profile, progress), ejected)

    def close():
        if busy:
            messagebox.showinfo('请等待', '正在处理操作，请等待返回结果。', parent=root)
        else:
            root.destroy()

    refresh.configure(command=refresh_list)
    eject.configure(command=do_eject, state='disabled')
    combo.bind('<<ComboboxSelected>>', selection)
    root.protocol('WM_DELETE_WINDOW', close)
    root.after(100, poll)
    root.after(0, refresh_list)
    root.mainloop()


if __name__ == '__main__':
    if os.name != 'nt':
        raise SystemExit('仅支持 Windows 11。')
    if sys.argv[1:] == ['--helper-once']:
        helper_once()
    elif len(sys.argv) == 3 and sys.argv[1] == '--install-helper':
        try:
            install_helper(sys.argv[2])
        except Exception as e:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror('初始化失败', str(e))
            root.destroy()
            raise SystemExit(1)
    elif sys.argv[1:] == ['--detect-only']:
        backend = Backend()
        try:
            disks, reasons = backend.scan()
            print(f'只读检测：{len(disks)} 个可识别 USB 磁盘；未执行任何状态改变操作。')
            for reason in reasons:
                print(reason)
            for disk in disks:
                print(f'{disk.device_path} | {disk.details}')
                try:
                    profile = backend.inspect(disk)
                    print(f'{disk.device_path} | {profile.model} | {profile.rpm} RPM | '
                          'SAT IDENTIFY 可用；停转支持未验证；机械停转状态未知。')
                except SafetyError as e:
                    print(f'{disk.device_path}：检测失败：{e}')
        except SafetyError as e:
            raise SystemExit(f'只读检测失败：{e}')
    elif sys.argv[1:]:
        raise SystemExit('用法：python safe_eject.py [--detect-only]')
    else:
        main()
