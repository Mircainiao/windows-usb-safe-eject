# Contributing

Bug reports and focused pull requests are welcome. Please describe the Windows version, Python version if relevant, exact application release, and steps to reproduce. Never include disk serial numbers, PnP instance paths, usernames, private logs, or file names from the disk.

Before submitting a change, run the mock-only tests:

```powershell
python -m unittest discover -s tests -v
python -m py_compile safe_eject.py desktop_app.py build.py tests\test_safe_eject.py tests\test_desktop_wrapper.py
```

These tests must not enumerate or control real disks. Do not add tests that lock volumes, dismount filesystems, send standby commands, or request PnP ejection. Package GUI checks should use the explicit read-only test entry and clearly state if device inspection may wake a drive.

Changes to disk identity checks, Windows API calls, the helper protocol, scheduled-task security, ACL policy, or privilege setup require careful security review. Keep control operations behind the existing explicit confirmation and keep the helper action allowlist fixed. Do not add vendor-specific stop commands or force-unmount behavior.

Please preserve third-party copyright and license notices. The top-level MIT license applies only to original project files. Do not relabel `smartctl` or other third-party code as MIT.
