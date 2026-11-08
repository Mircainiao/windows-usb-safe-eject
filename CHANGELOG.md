# Changelog

## v1.0.0 — 2026-11-08

- Initial public release for Windows 11 x64 with a Chinese tkinter GUI and standalone PyInstaller executable.
- Detects and validates USB physical disks and all mapped volumes; protects system, boot, paging-file, internal, ambiguous, and composite devices.
- Flushes and locks all associated volumes before dismounting; fails without force-unmounting when a volume is busy.
- Requests standard ATA/SAT standby when the bridge supports the command, reads one standby report, then requests whole-device Windows PnP removal.
- Reports Windows removal separately from standby command/status and never claims physical spindle stop is confirmed.
- Uses a protected, SID-authorized helper with strict request and reply ACLs. Existing v1 helper installations require an explicit source-based UAC update.
- Includes smartmontools 7.5, its GPL license and corresponding source archive, plus runtime third-party license notices.
