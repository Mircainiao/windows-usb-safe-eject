"""外壳异常/权限适配测试；不调用设备控制。"""
import hashlib
import importlib.util
import logging
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_wrapper_test', ROOT / 'desktop_app.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class WrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='usb-safe-eject-tests-')
        app.LOG_DIR = Path(cls.temp.name) / 'logs'
        app.BUNDLE = Path(cls.temp.name) / 'bundle'
        app.BUNDLE.mkdir()
        app.setup_logging()
        app.load_components()
        cls.original_eject = app.core.Backend.eject
        cls.original_lock = app.core.VolumeIO.lock
        cls.original_smart_init = app.core.Smartctl.__init__
        cls.original_helper_init = app.core.HelperClient.initialize
        cls.original_showerror = app.messagebox.showerror
        cls.original_askyesno = app.messagebox.askyesno
        cls.original_tk_exception = app.tk.Tk.report_callback_exception
        cls.original_sys_exception = sys.excepthook
        cls.original_thread_exception = app.core.threading.excepthook
        app.configure_frontend()

    @classmethod
    def tearDownClass(cls):
        app.core.Smartctl.__init__ = cls.original_smart_init
        app.core.HelperClient.initialize = cls.original_helper_init
        app.messagebox.showerror = cls.original_showerror
        app.messagebox.askyesno = cls.original_askyesno
        app.tk.Tk.report_callback_exception = cls.original_tk_exception
        sys.excepthook = cls.original_sys_exception
        app.core.threading.excepthook = cls.original_thread_exception
        for handler in list(logging.getLogger().handlers):
            handler.close()
            logging.getLogger().removeHandler(handler)
        cls.temp.cleanup()

    def test_original_source_and_control_functions_unchanged(self):
        self.assertEqual(hashlib.sha256(app.SOURCE.read_bytes()).hexdigest(),
                     '6c860342c0b97439db9149bf987e058e6f569a94467782e11ab9e8b679951c3c')
        self.assertIs(app.core.Backend.eject, type(self).original_eject)
        self.assertIs(app.core.VolumeIO.lock, type(self).original_lock)

    def test_frozen_initialization_cannot_rewrite_authorization(self):
        with patch.object(app.core, 'powershell') as ps:
            with self.assertRaises(app.core.SafetyError):
                app.core.HelperClient().initialize()
            ps.assert_not_called()

    def test_missing_bundled_tool_fails_without_path_fallback(self):
        with patch.object(app, 'BUNDLE', Path('no-such-bundle')):
            with self.assertRaises(app.core.SafetyError):
                app.core.Smartctl()

    def test_exception_is_displayed_and_persisted(self):
        with patch.object(app.messagebox, 'showerror') as dialog:
            try:
                raise RuntimeError('WRAPPER_TEST_DIAGNOSTIC')
            except RuntimeError:
                app.show_failure(*sys.exc_info())
            dialog.assert_called_once()
        for handler in logging.getLogger().handlers:
            handler.flush()
        self.assertIn('WRAPPER_TEST_DIAGNOSTIC', (app.LOG_DIR / 'desktop.log').read_text(encoding='utf-8'))

    def test_tk_callback_exception_hook_installed(self):
        self.assertTrue(callable(app.tk.Tk.report_callback_exception))
        self.assertIs(sys.excepthook, app.show_failure)

    def test_import_failure_occurs_after_logging_is_ready(self):
        for handler in list(logging.getLogger().handlers):
            handler.close()
            logging.getLogger().removeHandler(handler)
        with patch.object(app, 'load_components', side_effect=ImportError('BOOTSTRAP_IMPORT_TEST')), \
             patch.object(app.messagebox, 'showerror') as dialog:
            try:
                app.entry()
            except ImportError:
                app.show_failure(*sys.exc_info())
            dialog.assert_called_once()
        for handler in logging.getLogger().handlers:
            handler.flush()
        self.assertIn('BOOTSTRAP_IMPORT_TEST', (app.LOG_DIR / 'desktop.log').read_text(encoding='utf-8'))

    def test_cold_tk_failure_uses_native_message_box(self):
        with patch.object(app, 'messagebox', None), \
             patch.object(app.C.windll.user32, 'MessageBoxW') as native_dialog:
            app.show_failure(ImportError, ImportError('TK_LOAD_FAILED_TEST'), None)
            native_dialog.assert_called_once()
            self.assertIn('TK_LOAD_FAILED_TEST', native_dialog.call_args.args[1])

    def test_close_during_work_is_refused_by_original_gui(self):
        class Widget:
            def __init__(self, *args, **kwargs): pass
            def pack(self, **kwargs): pass
            def configure(self, **kwargs): pass
            def bind(self, *args): pass
            def current(self): return -1
            def set(self, value): pass
        root, tk = Mock(), types.ModuleType('tkinter')
        callbacks, protocols = [], {}
        root.after.side_effect = lambda delay, fn: callbacks.append((delay, fn))
        root.protocol.side_effect = lambda name, fn: protocols.update({name: fn})
        tk.Tk, tk.StringVar = lambda: root, Widget
        tk.ttk = types.SimpleNamespace(**{n: Widget for n in ('Frame','Label','Button','Combobox')})
        tk.messagebox = Mock()
        def loop():
            next(fn for delay, fn in callbacks if delay == 0)()
            protocols['WM_DELETE_WINDOW']()
        root.mainloop.side_effect = loop
        with patch.dict(sys.modules, {'tkinter': tk}), \
             patch.object(app.core, 'Backend'), \
             patch.object(app.core.threading, 'Thread', return_value=Mock()):
            app.core.main()
        root.destroy.assert_not_called()
        tk.messagebox.showinfo.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
