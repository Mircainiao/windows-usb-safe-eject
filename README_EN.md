# Windows USB Safe Eject

A small Chinese-language GUI for Windows 11 x64 that identifies external USB disks, flushes and releases their volumes, requests Windows PnP removal, and attempts a standard ATA/SAT standby command when the enclosure supports it.

**A successful Windows safe-removal request does not prove that the mechanical spindle has stopped.** Support depends on the USB-SATA bridge, driver, and drive firmware. Busy volumes are never forcibly dismounted, and no vendor-specific stop commands are used.

## Download and use

Download `USB-Safe-Eject.exe` from the [v1.0.0 release](https://github.com/Mircainiao/windows-usb-safe-eject/releases/tag/v1.0.0). GitHub normalizes non-ASCII asset names; this direct executable has the Chinese display label “USB硬盘安全退出.exe”. If you need the Chinese filename after extraction, download `USB-Safe-Eject-v1.0.0.zip`, which contains `USB硬盘安全退出.exe`. Both are Windows x64, windowed, single-file applications and do not require Python for ordinary use. Verify the SHA-256 against `SHA256SUMS.txt` before running. The executable is not Authenticode-signed.

Run as a normal user, select the disk, check its model, capacity, and all drive letters, then use **安全退出并停转**. The first click performs read-only identity checks and may wake a sleeping drive. A separate confirmation dialog is required before any disk-control operation. If Windows does not report successful device removal, do not power off the enclosure.

## Authorization and limitations

The GUI stays unelevated. A fixed, protected scheduled helper performs operations after explicit UAC authorization. The helper accepts only health, read-only inspection, and constrained eject requests; it does not expose a general command runner. The released EXE does not initialize or alter this task. A new computer needs a one-time setup using trusted source code and Python; see the Chinese README for the exact steps. The task is tied to the authorizing Windows SID and is not portable between computers.

Other processes running as that same authorized account can request the helper's fixed actions. The GUI confirmation is not a defense against malware in that account. Prior helper v1 users must explicitly run the v1.0.0 source and approve a UAC update; the EXE will not change existing authorization silently.

Only Windows 11 x64 has been verified. Disk detection requires an identifiable standalone USB storage device with unambiguous physical-disk and volume mappings. Active standby requires standard SAT ATA pass-through. Dynamic disks, Storage Spaces, RAID, composite USB devices, and unverified bridges are unsupported or conservatively rejected. Actual spindle speed cannot be independently measured after PnP removal.

Automated tests use mocks and do not touch real disks. The packaged smoke checks used read-only enumeration and simulated disconnection; they did not lock, dismount, stop, or eject a real disk. The local helper was still v1, so the new v2 EXE did not call it. The maintainer reports one manual safe-removal operation on an earlier private build, not on this public v1.0.0/v2 helper. The v2 initialization path was simulated but not applied to the existing local authorization. See [TESTING.md](TESTING.md).

## Source and build

Runtime Python dependencies: none beyond the standard library. Source mode requires Windows PowerShell and `smartctl >= 7.5`; a pinned smartctl binary is included under `packaging/`. Run `python safe_eject.py` after making it available on PATH. Build with Python 3.14.10 x64 using `build.ps1 onedir` followed by `build.ps1 onefile`; the script uses the pinned build lock file.

Original project code is MIT licensed. Third-party components keep their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The MIT license does not cover smartmontools.
