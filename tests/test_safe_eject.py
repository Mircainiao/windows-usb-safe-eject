"""纯模拟测试：不枚举、不打开、不移除任何真实磁盘。"""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import sys
import types
import json
import tempfile
import hashlib
import zipfile
from contextlib import nullcontext
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('safe_eject', ROOT / 'safe_eject.py')
s = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = s
spec.loader.exec_module(s)

USB = r'USB\VID_1234&PID_5678\SIMULATED'
PNP = r'USBSTOR\DISK&VEN_TEST\SIMULATED'
VOLUMES = [rf'\\?\Volume{{00000000-0000-0000-0000-{i:012d}}}' + '\\' for i in (1, 2)]
PROFILE = s.Profile('模拟机械硬盘', 'FAKE', 4000000000000, 7200)


def fixture():
    return {'disks': [dict(number=2, bus='USB', model='模拟机械硬盘', size='4000000000000',
        serial='FAKE', unique='FAKE-ID', pnp=PNP, boot=False, system=False,
        protected=False, offline=False, partitions=[
            dict(number=1, boot=False, system=False, paths=['E:\\', VOLUMES[0]]),
            dict(number=2, boot=False, system=False, paths=['F:\\', VOLUMES[1]])])],
        'physical': [dict(number=2, pnp=PNP), dict(number=0, pnp='INTERNAL')]}


class Simulation(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.native = Mock()
        self.native.usb_target.return_value = USB
        self.native.chain.return_value = [(1, 'INTERNAL')]
        self.native.io.open.side_effect = lambda path, write=False: 'handle:' + path
        self.native.io.volume_paths.return_value = VOLUMES
        self.native.io.extent_numbers.return_value = [2]
        self.smart = Mock()
        self.smart.identify.return_value = PROFILE
        self.smart.standby_report.return_value = True
        self.backend = s.Backend(self.native, lambda: copy.deepcopy(self.data), self.smart)

    def eject(self, selected):
        return self.backend.eject(selected, PROFILE, confirmed=True)

    def target(self):
        disks, reasons = self.backend.scan()
        self.assertFalse(reasons)
        return disks[0]

    def test_request_acl_denies_other_users_and_clears_inheritance(self):
        sid = 'S-1-5-21-1000-2000-3000-1001'
        clean = [
            {'sid': 'S-1-5-18', 'type': 'Allow', 'rights': 0x10000000},
            {'sid': 'S-1-5-32-544', 'type': 'Allow', 'rights': 0x10000000},
            {'sid': sid, 'type': 'Allow', 'rights': 0x3},
        ]
        s.validate_request_acl(clean, sid, inheritance_disabled=True)
        inherited_reader = clean + [
            {'sid': 'S-1-5-32-545', 'type': 'Allow', 'rights': 0x1},
        ]
        with self.assertRaises(s.SafetyError):
            s.validate_request_acl(inherited_reader, sid, inheritance_disabled=True)
        # A read-only legacy ACL may be inspected only during an explicit admin upgrade.
        s.validate_request_acl(inherited_reader, sid, inheritance_disabled=False, allow_legacy=True)
        inherited_writer = clean + [
            {'sid': 'S-1-5-11', 'type': 'Allow', 'rights': 0x2},
        ]
        with self.assertRaises(s.SafetyError):
            s.validate_request_acl(inherited_writer, sid, inheritance_disabled=False, allow_legacy=True)
        with self.assertRaises(s.SafetyError):
            s.validate_request_acl(clean[:-1], sid, inheritance_disabled=True)
        args = s.request_acl_icacls_args('request.json', sid)
        self.assertIn('/inheritance:r', args)
        self.assertIn('*S-1-5-18:(F)', args)
        self.assertIn('*S-1-5-32-544:(F)', args)
        self.assertIn(f'*{sid}:(R,W)', args)
        self.assertNotIn('*S-1-5-32-545:(R)', args)
        reply_acl = [
            {'sid': 'S-1-5-18', 'type': 'Allow', 'rights': 0x10000000},
            {'sid': 'S-1-5-32-544', 'type': 'Allow', 'rights': 0x10000000},
            {'sid': sid, 'type': 'Allow', 'rights': 0x1},
        ]
        s.validate_reply_acl(reply_acl, sid, inheritance_disabled=True)
        with self.assertRaises(s.SafetyError):
            s.validate_reply_acl(reply_acl + [inherited_reader[-1]], sid, inheritance_disabled=True)
        self.assertEqual(s.reply_acl_icacls_args('reply.json', sid)[-1], f'*{sid}:(R)')

    @unittest.skipUnless(sys.platform == 'win32', 'Windows ACL integration check')
    def test_icacls_applies_protected_request_and_reply_acl_to_temp_files(self):
        sid = s.user_sid()
        with tempfile.TemporaryDirectory() as tmp:
            request = Path(tmp) / 'request.json'
            reply = Path(tmp) / 'reply.json'
            request.write_text('{}', encoding='utf-8')
            reply.write_text('{}', encoding='utf-8')
            s.set_ipc_file_acl(request, sid, 'R,W')
            s.set_ipc_file_acl(reply, sid, 'R')

            def read_acl(path):
                report = json.loads(s.powershell(f"""
$a=Get-Acl -LiteralPath {s.ps_quote(path)};
$entries=@($a.Access | ForEach-Object {{
 [pscustomobject]@{{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;
 type=$_.AccessControlType.ToString(); rights=[int64]$_.FileSystemRights}}
}});
[pscustomobject]@{{protected=[bool]$a.AreAccessRulesProtected; entries=$entries}} |
 ConvertTo-Json -Depth 4 -Compress
"""))
                return report

            request_acl = read_acl(request)
            reply_acl = read_acl(reply)
            self.assertIs(request_acl['protected'], True)
            self.assertIs(reply_acl['protected'], True)
            s.validate_request_acl(request_acl['entries'], sid, True)
            s.validate_reply_acl(reply_acl['entries'], sid, True)

    def test_installation_verifies_request_acl_report(self):
        sid = 'S-1-5-21-1000-2000-3000-1001'
        entries = [
            {'sid': 'S-1-5-18', 'type': 'Allow', 'rights': 0x10000000},
            {'sid': 'S-1-5-32-544', 'type': 'Allow', 'rights': 0x10000000},
            {'sid': sid, 'type': 'Allow', 'rights': 0x3},
        ]
        reply_entries = [dict(entries[0]), dict(entries[1]),
                         {'sid': sid, 'type': 'Allow', 'rights': 0x1}]
        report = {'ipc': {
            'request.json': {'protected': True, 'entries': entries},
            'reply.json': {'protected': True, 'entries': reply_entries},
            'reply.tmp': None,
        }}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'config.json').write_text(json.dumps(
                {'sid': sid, 'version': s.HELPER_VERSION, 'hashes': {}}), encoding='utf-8')
            with patch.object(s, 'powershell', return_value=json.dumps(report)) as run:
                s.verify_installation(root)
            script = run.call_args.args[0]
            self.assertIn('AreAccessRulesProtected', script)
            self.assertIn('reply.json', script)
            self.assertIn('reply.tmp', script)

    def test_admin_upgrade_accepts_legacy_read_only_acl_but_not_write(self):
        sid = 'S-1-5-21-1000-2000-3000-1001'
        legacy_entries = [
            {'sid': sid, 'type': 'Allow', 'rights': 0x3},
            {'sid': 'S-1-5-32-545', 'type': 'Allow', 'rights': 0x1},
        ]
        legacy_reply_entries = [
            {'sid': sid, 'type': 'Allow', 'rights': 0x1},
            {'sid': 'S-1-5-32-545', 'type': 'Allow', 'rights': 0x1},
        ]
        legacy_reader = {'ipc': {
            'request.json': {'protected': False, 'entries': legacy_entries},
            'reply.json': {'protected': False, 'entries': legacy_reply_entries},
            'reply.tmp': None,
        }}
        legacy_writer = {'ipc': {
            'request.json': {'protected': False, 'entries': [
                {'sid': sid, 'type': 'Allow', 'rights': 0x3},
                {'sid': 'S-1-5-11', 'type': 'Allow', 'rights': 0x2},
            ]},
            'reply.json': {'protected': False, 'entries': legacy_reply_entries},
            'reply.tmp': None,
        }}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(s, 'admin', return_value=True), \
             patch.object(s, 'powershell', return_value=json.dumps(legacy_reader)) as run:
            config = s.verify_installation(Path(tmp), allow_incomplete=True, sid=sid)
            self.assertEqual(config['sid'], sid)
            self.assertIn('request.json', run.call_args.args[0])
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(s, 'admin', return_value=True), \
             patch.object(s, 'powershell', return_value=json.dumps(legacy_writer)):
            with self.assertRaises(s.SafetyError):
                s.verify_installation(Path(tmp), allow_incomplete=True, sid=sid)

    def test_reply_temp_is_acl_protected_before_sensitive_data_is_written(self):
        sid = 'S-1-5-21-1000-2000-3000-1001'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def secure_before_write(path, authorized_sid, rights):
                self.assertEqual(authorized_sid, sid)
                self.assertEqual(rights, 'R')
                self.assertEqual(path.read_bytes(), b'')
            with patch.object(s, 'set_ipc_file_acl', side_effect=secure_before_write):
                s.write_reply(root, {'value': {'serial': 'SIMULATED'}}, sid)
            saved = json.loads((root / 'reply.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['value']['serial'], 'SIMULATED')
            self.assertFalse((root / 'reply.tmp').exists())

    def test_two_partitions_one_request_for_whole_device(self):
        target = self.target()
        self.assertEqual(target.paths, ('E:\\', 'F:\\'))
        text = self.eject(target)
        self.native.request_eject.assert_called_once_with(USB)
        self.assertIn('Windows 已完成设备安全移除', text)
        self.assertIn('机械停转状态未知', text)

    def test_protected_and_unknown_flags_rejected(self):
        for field in ('boot', 'system', 'protected', 'offline'):
            for value in (True, None):
                with self.subTest(field=field, value=value):
                    self.data = fixture()
                    self.data['disks'][0][field] = value
                    disks, reasons = self.backend.scan()
                    self.assertEqual(disks, [])
                    self.assertTrue(reasons)
        self.native.request_eject.assert_not_called()

    def test_internal_disk_excluded(self):
        self.data['disks'][0]['bus'] = 'SATA'
        self.assertEqual(self.backend.scan()[0], [])
        self.native.usb_target.assert_not_called()

    def test_missing_serial_and_unique_id_rejected(self):
        self.data['disks'][0].update(serial=' ', unique='')
        self.assertEqual(self.backend.scan()[0], [])
        self.native.request_eject.assert_not_called()

    def test_protected_partition(self):
        self.data['disks'][0]['partitions'][1]['system'] = True
        self.assertEqual(self.backend.scan()[0], [])

    def test_multiple_physical_disks_same_usb_rejected(self):
        self.native.chain.return_value = [(4, USB)]
        self.assertEqual(self.backend.scan()[0], [])

    def test_disk_identity_or_partition_changed(self):
        for field, value in [('serial', 'OTHER'), ('pnp', 'OTHER'),
                             ('number', 3), ('size', '8000000000000')]:
            self.data = fixture()
            selected = self.target()
            self.data['disks'][0][field] = value
            with self.subTest(field=field), self.assertRaises(s.SafetyError):
                self.eject(selected)
        self.data = fixture()
        selected = self.target()
        self.data['disks'][0]['partitions'].pop()
        with self.assertRaises(s.SafetyError):
            self.eject(selected)
        self.native.request_eject.assert_not_called()

    def test_missing_device_and_retry(self):
        selected = self.target()
        self.data['disks'] = []
        with self.assertRaises(s.SafetyError):
            self.eject(selected)
        self.native.request_eject.assert_not_called()
        self.data = fixture()
        self.eject(self.target())
        self.native.request_eject.assert_called_once()

    def test_unsupported_and_query_error(self):
        self.native.usb_target.side_effect = s.SafetyError('不支持')
        self.assertEqual(self.backend.scan()[0], [])
        self.backend.reader = Mock(side_effect=s.SafetyError('查询失败'))
        with self.assertRaises(s.SafetyError):
            self.backend.scan()
        self.native.request_eject.assert_not_called()

    def test_veto_never_reports_success(self):
        # 用假的 DLL 对象测试实际 request_eject 包装函数，绝不加载 Native()。
        native = object.__new__(s.Native)
        native.locate = Mock(return_value=123)
        native.cm = Mock()

        def veto(node, kind, name, length, flags):
            C.cast(kind, C.POINTER(C.c_int))[0] = 5
            name.value = '模拟占用对象'
            self.assertEqual((node, length, flags), (123, 260, 0))
            return 0x17
        native.cm.CM_Request_Device_EjectW.side_effect = veto
        with self.assertRaisesRegex(s.SafetyError, '仍有打开的文件或设备句柄'):
            native.request_eject(USB)
        native.cm.CM_Request_Device_EjectW.side_effect = None
        native.cm.CM_Request_Device_EjectW.return_value = 0
        native.request_eject(USB)

    def test_usb_target_checks_service_removability_and_composite(self):
        native = object.__new__(s.Native)
        native.chain = Mock(return_value=[(1, PNP), (2, USB)])
        native.prop = Mock(side_effect=['UASPStor', 4])
        self.assertEqual(native.usb_target(PNP), USB)
        for service, caps in [('USBHUB3', 4), ('USBSTOR', 0)]:
            native.prop.side_effect = [service, caps]
            with self.assertRaises(s.SafetyError):
                native.usb_target(PNP)
        native.chain.return_value = [(2, r'USB\VID_1234&PID_5678&MI_00\FAKE')]
        with self.assertRaises(s.SafetyError):
            native.usb_target(PNP)

    def test_read_only_enumerator_failure_and_unicode(self):
        payload = __import__('json').dumps(self.data).encode('utf-8')
        with patch.object(s.subprocess, 'run', return_value=Mock(returncode=0, stdout=payload)) as run:
            self.assertEqual(s.inventory(), self.data)
            self.assertIn('-EncodedCommand', run.call_args.args[0])
        with patch.object(s.subprocess, 'run', return_value=Mock(returncode=1, stderr=b'denied')):
            with self.assertRaises(s.SafetyError):
                s.inventory()

    def test_gui_requires_explicit_confirmation(self):
        # 不创建真实窗口；运行 GUI 的选择、取消、确认和结果处理路径。
        for confirmed in (False, True):
            with self.subTest(confirmed=confirmed):
                widgets, callbacks = [], []

                class Widget:
                    def __init__(self, *args, **kwargs):
                        self.options = kwargs
                        self.index = -1
                        widgets.append(self)

                    def __setitem__(self, key, value):
                        self.options[key] = value

                    def current(self, index=None):
                        if index is not None:
                            self.index = index
                        return self.index

                    def configure(self, **kwargs):
                        self.options.update(kwargs)

                    def set(self, value):
                        self.value = value

                    def pack(self, **kwargs):
                        pass

                    def bind(self, *args):
                        pass

                root = Mock()
                root.after.side_effect = lambda delay, fn: callbacks.append((delay, fn))
                tk = types.ModuleType('tkinter')
                tk.Tk = lambda: root
                tk.StringVar = Widget
                tk.ttk = types.SimpleNamespace(**{n: Widget for n in
                    ('Frame', 'Label', 'Combobox', 'Button')})
                tk.messagebox = Mock()
                tk.messagebox.askyesno.return_value = confirmed
                backend = Mock()
                backend.scan.return_value = ([self.target()], [])
                backend.eject.return_value = '模拟完成'
                backend.inspect.return_value = PROFILE

                def loop():
                    next(fn for delay, fn in callbacks if delay == 0)()
                    next(fn for delay, fn in callbacks if delay == 100)()
                    button = next(w for w in widgets if w.options.get('text') == '安全退出并停转')
                    button.options['command']()
                    next(fn for delay, fn in callbacks if delay == 100)()
                    backend.eject.assert_not_called()  # 首次按钮只检测
                    tk.messagebox.askyesno.assert_not_called()
                    button.options['command']()
                    next(fn for delay, fn in callbacks if delay == 100)()

                root.mainloop.side_effect = loop
                fake_thread = lambda target, **kw: types.SimpleNamespace(start=target)
                with patch.dict(sys.modules, {'tkinter': tk}), \
                     patch.object(s, 'Backend', return_value=backend), \
                     patch.object(s, 'admin', return_value=True), \
                     patch.object(s.threading, 'Thread', side_effect=fake_thread):
                    s.main(auto_confirm=False)
                tk.messagebox.askyesno.assert_called_once()
                if confirmed:
                    args, kwargs = backend.eject.call_args
                    self.assertEqual(args, (self.target(), PROFILE))
                    self.assertTrue(kwargs['confirmed'])
                    self.assertEqual(tk.messagebox.showinfo.call_count, 2)
                else:
                    backend.eject.assert_not_called()

    def test_no_confirmation_or_read_only_inspection_never_mutates(self):
        disk = self.target()
        self.backend.inspect(disk)
        with self.assertRaises(s.SafetyError):
            self.backend.eject(disk, PROFILE)
        for name in ('flush', 'lock', 'dismount'):
            getattr(self.native.io, name).assert_not_called()
        self.smart.stop.assert_not_called()
        self.native.request_eject.assert_not_called()

    def test_pipeline_order_and_no_queries_after_stop(self):
        log = []
        for name in ('flush', 'lock', 'dismount', 'close', 'verify_disk'):
            getattr(self.native.io, name).side_effect = lambda *a, n=name: log.append(n)
        self.smart.stop.side_effect = lambda *a: log.append('stop')
        self.smart.standby_report.side_effect = lambda *a: log.append('power') or True
        self.smart.identify.side_effect = lambda *a: log.append('identify') or PROFILE
        self.native.request_eject.side_effect = lambda *a: log.append('pnp')
        self.eject(self.target())
        self.assertEqual(log.count('lock'), 2)
        self.assertLess(max(i for i, x in enumerate(log) if x == 'lock'), log.index('dismount'))
        self.assertEqual(log[log.index('stop'):], ['stop', 'power', 'close', 'close', 'close', 'pnp'])

    def test_pre_stop_failure_never_stops_or_ejects(self):
        for name in ('flush', 'lock', 'dismount'):
            with self.subTest(stage=name):
                self.setUp()
                getattr(self.native.io, name).side_effect = [None, s.SafetyError('模拟失败')]
                with self.assertRaises(s.SafetyError):
                    self.eject(self.target())
                self.smart.stop.assert_not_called()
                self.native.request_eject.assert_not_called()
                self.assertEqual(self.native.io.close.call_count, 4)  # inspect + 磁盘 + 两卷
                if name == 'lock':
                    self.native.io.dismount.assert_not_called()

    def test_stop_failure_still_safely_removes_with_explicit_result(self):
        self.smart.stop.side_effect = s.SafetyError('桥接不支持')
        text = self.eject(self.target())
        self.assertIn('主动停转请求失败', text)
        self.native.request_eject.assert_called_once()
        self.smart.standby_report.assert_not_called()

    def test_pnp_failure_is_not_success(self):
        self.native.request_eject.side_effect = s.SafetyError('被拒绝')
        with self.assertRaisesRegex(s.SafetyError, '请勿断电'):
            self.eject(self.target())

    def test_cross_disk_and_missing_volume_rejected(self):
        self.native.io.volume_paths.return_value = VOLUMES[:1]
        with self.assertRaises(s.SafetyError):
            self.eject(self.target())
        self.native.io.volume_paths.return_value = VOLUMES
        self.native.io.extent_numbers.return_value = [0, 2]
        with self.assertRaises(s.SafetyError):
            self.eject(self.target())
        self.smart.stop.assert_not_called()

    def test_ata_identity_change_after_locks(self):
        self.smart.identify.side_effect = [PROFILE, s.Profile('另一个型号', 'OTHER', PROFILE.size, 7200)]
        with self.assertRaises(s.SafetyError):
            self.eject(self.target())
        self.smart.stop.assert_not_called()

    def test_standby_report_requires_exact_evidence(self):
        smart = object.__new__(s.Smartctl)
        for code, mode, name, expected in [(3, 0, 'STANDBY', True),
                (3, 1, 'STANDBY_Y', False), (3, -1, 'SLEEP', False),
                (3, None, 'STANDBY (OS)', False), (0, 0, 'STANDBY', False)]:
            smart.call = Mock(return_value=(code, {'power_mode': {'ata_value': mode, 'name': name}}))
            self.assertEqual(smart.standby_report(self.target()), expected)

    def test_tool_commands_fixed_sat_and_no_vendor_fallback(self):
        smart = object.__new__(s.Smartctl)
        smart.exe = 'mock-smartctl.exe'
        raw = b'{"smartctl":{"version":[7,5]}}'
        with patch.object(s.subprocess, 'run', return_value=Mock(returncode=0, stdout=raw)) as run:
            smart.stop(self.target())
            self.assertEqual(run.call_args.args[0],
                ['mock-smartctl.exe', '-j', '-d', 'sat', '-s', 'standby,now', '/dev/pd2'])

    def test_ata_identify_rejects_ssd_wrong_device_and_capacity(self):
        smart = object.__new__(s.Smartctl)
        base = {'device': {'protocol': 'ATA', 'type': 'sat', 'name': '/dev/pd2'},
                'model_name': PROFILE.model, 'serial_number': PROFILE.serial,
                'rotation_rate': 7200, 'user_capacity': {'bytes': PROFILE.size}}
        smart.call = Mock(return_value=(0, base))
        self.assertEqual(smart.identify(self.target()), PROFILE)
        for key, value in [('rotation_rate', 0), ('serial_number', ''),
                ('user_capacity', {'bytes': PROFILE.size + 512}),
                ('device', {'protocol': 'ATA', 'type': 'sat', 'name': '/dev/pd0'})]:
            smart.call.return_value = (0, dict(base, **{key: value}))
            with self.subTest(key=key), self.assertRaises(s.SafetyError):
                smart.identify(self.target())

    def test_native_mapping_and_descriptor_mismatch_rejected(self):
        import struct
        io = object.__new__(s.VolumeIO)
        descriptor = bytearray(36)
        struct.pack_into('<I', descriptor, 28, 7)
        disk = self.target()
        good = [struct.pack('<III', 7, 2, 0xffffffff), bytes(descriptor),
                struct.pack('<q', PROFILE.size)]
        io.ioctl = Mock(side_effect=good)
        io.verify_disk('fake', disk)
        io.ioctl.side_effect = [struct.pack('<III', 7, 0, 0xffffffff)]
        with self.assertRaises(s.SafetyError):
            io.verify_disk('fake', disk)
        self.assertEqual(s.Extents.items.offset, 8)
        self.assertEqual(C.sizeof(s.Extent), 24)
        raw = bytearray(8 + 24)
        struct.pack_into('<I', raw, 0, 1)
        struct.pack_into('<I', raw, 8, 2)
        io.ioctl = Mock(return_value=bytes(raw))
        self.assertEqual(io.extent_numbers('fake'), [2])
        io.ioctl.return_value = bytes(raw[:12])
        with self.assertRaises(s.SafetyError):
            io.extent_numbers('fake')

    def test_close_failure_blocks_pnp(self):
        disk = self.target()
        # inspect 自身关闭正常；实际操作关闭失败时不继续 PnP。
        self.native.io.close.side_effect = [None, s.SafetyError('close failure'), None, None]
        with self.assertRaisesRegex(s.SafetyError, '句柄清理失败'):
            self.eject(disk)
        self.native.request_eject.assert_not_called()

    def test_fsctl_has_null_input_and_output_buffers(self):
        io = object.__new__(s.VolumeIO)
        io.k = Mock()
        def control(h, code, inp, in_size, out, out_size, returned, overlapped):
            self.assertEqual((inp, in_size, out, out_size, overlapped), (None, 0, None, 0, None))
            self.assertIn(code, (0x90018, 0x90020))
            return True
        io.k.DeviceIoControl.side_effect = control
        io.lock('fake')
        io.dismount('fake')

    def request(self, action='inspect'):
        return json.loads(json.dumps(dict(version=s.HELPER_VERSION, nonce='a' * 32,
            time=s.time.time(), action=action, disk=s.asdict(self.target()),
            profile=s.asdict(PROFILE) if action == 'eject' else None)))

    def test_inspection_requests_zero_access_and_never_length_ioctl(self):
        self.backend.inspect(self.target())
        self.native.io.open.assert_called_once_with(self.target().device_path)
        self.native.io.verify_metadata.assert_called_once()
        self.native.io.verify_disk.assert_not_called()
        io = object.__new__(s.VolumeIO)
        io.k = Mock()
        io.k.CreateFileW.return_value = 123
        io.open(r'\\.\PhysicalDrive97')
        self.assertEqual(io.k.CreateFileW.call_args.args[1], 0)

    def test_error_classification_does_not_equate_all_access_denied_with_admin(self):
        with patch.object(C, 'get_last_error', return_value=5):
            e = s.VolumeIO.error('锁卷 FSCTL_LOCK_VOLUME')
            self.assertIn('可能占用', e.category)
            e = s.VolumeIO.error('CreateFileW', 'fake', 0)
            self.assertIn('ACL', e.category)
            self.assertIn('0x00000000', str(e))
        with patch.object(C, 'get_last_error', return_value=32):
            self.assertEqual(s.VolumeIO.error('open').category, '硬盘被占用')
        with patch.object(C, 'get_last_error', return_value=50):
            self.assertIn('不支持', s.VolumeIO.error('ioctl').category)

    def test_request_rejects_command_injection_replay_stale_and_wrong_types(self):
        request = self.request('eject')
        disk, profile = s.validate_request(request)
        self.assertEqual((disk, profile), (self.target(), PROFILE))
        mutations = [dict(command='cmd.exe'), dict(action='exec'), dict(time=0),
                     dict(nonce='../../request'), dict(profile={'rpm': 7200})]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(s.SafetyError):
                s.validate_request(dict(request, **change))
        with self.assertRaises(s.SafetyError):
            s.validate_request(request, request['nonce'])
        request['disk']['number'] = '2 & cmd'
        with self.assertRaises(s.SafetyError):
            s.validate_request(request)

    def scratch(self):
        base = Path(__file__).resolve().parents[1] / 'work'
        base.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(dir=base)

    def test_helper_read_only_dispatch_does_not_control_devices(self):
        with self.scratch() as temp:
            root = Path(temp)
            (root / 'reply.json').write_text('{}', encoding='utf-8')
            with patch.object(s, 'helper_root', return_value=root), \
                 patch.object(s, '__file__', str(root / 'safe_eject.py')), \
                 patch.object(s, 'admin', return_value=True), \
                 patch.object(s, 'verify_installation', return_value={
                     'installed': True, 'sid': 'S-1-5-21-1-2-3-1001'}), \
                 patch.object(s, 'read_fixed_request', return_value=self.request()), \
                 patch.object(s, 'set_ipc_file_acl'), \
                 patch.object(s, 'Backend', return_value=self.backend):
                s.helper_once()
            reply = json.loads((root / 'reply.json').read_text(encoding='utf-8'))
            self.assertEqual(reply['state'], 'result')
            self.assertEqual(reply['value'], s.asdict(PROFILE))
        self.native.io.lock.assert_not_called()
        self.smart.stop.assert_not_called()
        self.native.request_eject.assert_not_called()

    def test_helper_revalidates_identity_and_preserves_multivolume_sequence(self):
        for changed in (True, False):
            self.setUp()
            request = self.request('eject')
            if changed:
                self.data['disks'][0]['model'] = 'CHANGED'
            with self.scratch() as temp:
                root = Path(temp)
                (root / 'reply.json').write_text('{}', encoding='utf-8')
                with patch.object(s, 'helper_root', return_value=root), \
                     patch.object(s, '__file__', str(root / 'safe_eject.py')), \
                     patch.object(s, 'admin', return_value=True), \
                     patch.object(s, 'verify_installation', return_value={
                         'installed': True, 'sid': 'S-1-5-21-1-2-3-1001'}), \
                     patch.object(s, 'read_fixed_request', return_value=request), \
                     patch.object(s, 'set_ipc_file_acl'), \
                     patch.object(s, 'enable_load_privilege'), \
                     patch.object(s, 'Backend', return_value=self.backend):
                    s.helper_once()
                reply = json.loads((root / 'reply.json').read_text(encoding='utf-8'))
                self.assertEqual(reply['state'], 'error' if changed else 'result')
            if changed:
                self.smart.stop.assert_not_called()
            else:
                self.assertEqual(self.native.io.lock.call_count, 2)
                self.native.request_eject.assert_called_once()

    def test_initialization_uac_cancel_does_not_start_helper(self):
        client = s.HelperClient()
        with patch.object(s, 'user_sid', return_value='S-1-5-21-1-2-3-1001'), \
             patch.object(s, 'powershell', side_effect=s.SafetyError('UAC cancelled')), \
             patch.object(client, 'call') as call:
            with self.assertRaisesRegex(s.DeviceError, '权限提升失败'):
                client.initialize()
            call.assert_not_called()

    def test_install_requires_explicit_elevation(self):
        with patch.object(s, 'admin', return_value=False), patch.object(s, 'helper_root') as root:
            with self.assertRaises(s.SafetyError):
                s.install_helper('S-1-5-21-1-2-3-1001')
            root.assert_not_called()

    def test_first_initialization_deploys_fixed_isolated_task_only(self):
        with self.scratch() as temp:
            base, sid = Path(temp), 'S-1-5-21-1-2-3-1001'
            archive, smart = base / 'runtime.zip', base / 'smartctl.exe'
            smart.write_bytes(b'fake smartctl, never execute')
            with zipfile.ZipFile(archive, 'w') as package:
                package.writestr('python.exe', b'fake, never execute')
            scripts, commands = [], []
            def download(url, target):
                target.write_bytes(archive.read_bytes())
            def command(args, **kwargs):
                commands.append(args)
                return Mock(returncode=0)
            with patch.object(s, 'admin', return_value=True), \
                 patch.object(s, 'protect_new_file_owners'), \
                 patch.object(s, 'helper_root', return_value=base / 'protected'), \
                 patch.object(s, 'RUNTIME_HASH', hashlib.sha256(archive.read_bytes()).hexdigest()), \
                 patch.object(s, 'SMART_HASH', hashlib.sha256(smart.read_bytes()).hexdigest()), \
                 patch.object(s.urllib.request, 'urlretrieve', side_effect=download), \
                 patch.object(s, 'Smartctl', return_value=Mock(exe=str(smart))), \
                 patch.object(s, 'verify_installation'), \
                 patch.object(s, 'powershell', side_effect=lambda script, **kw: scripts.append(script)), \
                 patch.object(s.subprocess, 'run', side_effect=command):
                s.install_helper(sid)
            script = scripts[-1]
            self.assertIn('--helper-once', script)
            self.assertIn('-I -S', script)
            self.assertIn('GRGX', script)
            self.assertIn("UserId='SYSTEM'", script)
            self.assertNotIn('$(Arg', script)
            self.assertEqual((base / 'protected/python314._pth').read_text(), 'python314.zip\n.\n')
            self.assertTrue(any('/setowner' in args for args in commands))
            # 导出只用于 PowerShell 语法解析；不执行注册/ACL脚本。
            (Path(__file__).resolve().parents[1] / 'work/setup-task-syntax.ps1').write_text(script, encoding='utf-8-sig')

    def test_task_permission_failure_and_running_task_fail_closed(self):
        client = s.HelperClient()
        with self.scratch() as temp:
            root, sid = Path(temp), 'S-1-5-21-1-2-3-1001'
            for reply in ('4', s.SafetyError('task permission denied')):
                with patch.object(s, 'helper_mutex', return_value=nullcontext()), \
                     patch.object(s, 'helper_root', return_value=root), \
                     patch.object(s, 'verify_installation', return_value={'sid': sid, 'installed': True}), \
                     patch.object(s, 'user_sid', return_value=sid), \
                     patch.object(s, 'powershell', side_effect=[reply]):
                    with self.assertRaises(s.SafetyError):
                        client.call('inspect', self.target())
                self.assertFalse((root / 'request.json').exists())

    def test_unsafe_acl_or_runtime_hash_is_rejected_before_task(self):
        client = s.HelperClient()
        with patch.object(s, 'helper_mutex', return_value=nullcontext()), \
             patch.object(s, 'helper_root', return_value=Path('unused')), \
             patch.object(s, 'verify_installation', side_effect=s.SafetyError('Unsafe owner')), \
             patch.object(s, 'powershell') as ps:
            with self.assertRaises(s.SafetyError):
                client.call('inspect', self.target())
            ps.assert_not_called()

    def test_reply_nonce_is_required_and_task_exit_is_not_success(self):
        client, sid = s.HelperClient(), 'S-1-5-21-1-2-3-1001'
        for matching in (True, False):
            with self.scratch() as temp:
                root = Path(temp)
                def ps(script):
                    if '.Run(' in script:
                        request = json.loads((root / 'request.json').read_text())
                        reply = dict(nonce=request['nonce'] if matching else 'old', state='result', value='模拟成功')
                        (root / 'reply.json').write_text(json.dumps(reply), encoding='utf-8')
                        return ''
                    return '3'
                with patch.object(s, 'helper_mutex', return_value=nullcontext()), \
                     patch.object(s, 'helper_root', return_value=root), \
                     patch.object(s, 'verify_installation', return_value={'sid': sid, 'installed': True}), \
                     patch.object(s, 'user_sid', return_value=sid), \
                     patch.object(s, 'powershell', side_effect=ps), \
                     patch.object(s.time, 'sleep'), \
                     patch.object(s.time, 'monotonic', side_effect=[0, 1, 301]):
                    if matching:
                        self.assertEqual(client.call('inspect', self.target()), '模拟成功')
                    else:
                        with self.assertRaisesRegex(s.SafetyError, '执行状态未知'):
                            client.call('inspect', self.target())

    def test_ordinary_gui_initializes_then_delegates_without_elevating_gui(self):
        for cancel in (False, True):
            widgets, callbacks = [], []
            class Widget:
                def __init__(self, *args, **kwargs):
                    self.options, self.index = kwargs, -1
                    widgets.append(self)
                def __setitem__(self, key, value): self.options[key] = value
                def current(self, index=None):
                    if index is not None: self.index = index
                    return self.index
                def configure(self, **kwargs): self.options.update(kwargs)
                def set(self, value): self.value = value
                def pack(self, **kwargs): pass
                def bind(self, *args): pass
            tk, root = types.ModuleType('tkinter'), Mock()
            tk.Tk, tk.StringVar = lambda: root, Widget
            tk.ttk = types.SimpleNamespace(**{n: Widget for n in ('Frame', 'Label', 'Combobox', 'Button')})
            tk.messagebox = Mock()
            tk.messagebox.askyesno.return_value = True
            root.after.side_effect = lambda delay, fn: callbacks.append((delay, fn))
            backend, helper = Mock(), Mock()
            backend.scan.return_value = ([self.target()], [])
            helper.ready.return_value = False
            if cancel:
                helper.initialize.side_effect = s.SafetyError('权限提升取消')
            helper.call.side_effect = lambda action, *args: s.asdict(PROFILE) if action == 'inspect' else '模拟安全移除完成'
            def loop():
                next(fn for delay, fn in callbacks if delay == 0)()
                poll = next(fn for delay, fn in callbacks if delay == 100)
                poll()
                next(w for w in widgets if w.options.get('text') == '安全退出并停转').options['command']()
                poll()
                if not cancel:
                    poll()
            root.mainloop.side_effect = loop
            with patch.dict(sys.modules, {'tkinter': tk}), \
                 patch.object(s, 'Backend', return_value=backend), \
                 patch.object(s, 'HelperClient', return_value=helper), \
                 patch.object(s, 'admin', return_value=False), \
                 patch.object(s.threading, 'Thread', side_effect=lambda target, **kw: types.SimpleNamespace(start=target)):
                s.main()
            helper.initialize.assert_called_once()
            backend.eject.assert_not_called()
            if cancel:
                helper.call.assert_not_called()
                tk.messagebox.showerror.assert_called_once()
            else:
                self.assertEqual([call.args[0] for call in helper.call.call_args_list], ['inspect', 'eject'])
                self.assertEqual(tk.messagebox.askyesno.call_count, 2)

    def test_windows_powershell_module_environment_is_isolated(self):
        with patch.dict(s.os.environ, {'PSModulePath': r'C:\untrusted\modules'}), \
             patch.object(s, 'system_tool', side_effect=lambda p: str(Path(r'C:\Windows\System32') / p)), \
             patch.object(s, 'helper_root', return_value=Path(r'C:\Program Files\UsbSafeEject')), \
             patch.object(s.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'OK')) as run:
            self.assertEqual(s.powershell('Write-Output OK'), 'OK')
            env = run.call_args.kwargs['env']
            self.assertNotIn('untrusted', env['PSModulePath'])
            self.assertIn('WindowsPowerShell', env['PSModulePath'])
            self.assertEqual(s.os.environ['PSModulePath'], r'C:\untrusted\modules')


if __name__ == '__main__':
    unittest.main(verbosity=2)
