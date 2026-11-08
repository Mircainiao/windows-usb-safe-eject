# Security policy

## Supported version

Security fixes are made on the default branch and released as a new version. Reporters should include the affected release and Windows version, but remove disk serial numbers, PnP instance IDs, user names, drive contents, and unredacted logs.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting / Security Advisories for this repository when available. If private reporting is not enabled, contact the maintainer through the contact route on the GitHub profile before opening a public issue. Do not publish an exploit or include local disk identifiers in a public report.

The desktop log is stored under `%LOCALAPPDATA%\UsbSafeEject\logs\`. It can include device models, drive paths, Windows error details, and local file paths. Inspect and redact it before sharing.

## Security boundaries and known limitations

- The helper uses a fixed Task Scheduler action and accepts only `health`, `inspect`, and `eject`. It does not run arbitrary commands or accept executable paths from IPC data.
- The helper runs from an administrator-owned protected directory, checks owner, ACLs, reparse points, hashes, request schema, freshness, nonce, and the current disk identity before a control operation.
- In helper v2, `request.json`, `reply.json`, and `reply.tmp` have protected, non-inheriting ACLs. Only SYSTEM, Administrators, and the authorized SID can access them; the authorized SID can write requests and read replies. The helper rejects broad reader ACEs. A v1-to-v2 update is performed only after the user runs the trusted source and approves UAC.
- The helper is intentionally authorized for a Windows SID, not for one GUI process. Other processes running as that same SID can request its fixed operations. The GUI confirmation is a usability safeguard, not a security boundary against malware running as the authorized user.
- First-time installation launches the current Python interpreter and `safe_eject.py` after a visible UAC prompt, then copies verified files to the protected directory. The source code is not Authenticode-signed; users must obtain and verify it from the official repository before approving UAC.
- Disk safety depends on Windows, storage drivers, USB bridge firmware, and hardware reporting. Safe removal cannot prove the spindle is physically stopped, and PnP removal can cause later device access.
- A prior unpublished helper v1 inherited read access for other local users on its IPC request/reply files. That could expose disk identifiers to other local accounts. The v1.0.0 helper v2 explicitly removes this access and validates both IPC ACLs. Existing installations are not modified automatically; run the v1.0.0 source and approve the update to apply the fix.

This project has not received a formal third-party security certification. Automated tests and one maintainer-reported manual operation do not prove the absence of vulnerabilities or broad hardware compatibility.
