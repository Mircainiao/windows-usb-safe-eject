# Third-party components and licenses

The top-level [MIT License](LICENSE) applies only to original project code and project-created assets. Third-party software retains its own license. The single-file executable carries the runtime notices and smartmontools source archive; startup also copies these files to `%LOCALAPPDATA%\UsbSafeEject\licenses\`.

| Component | Use | License/material |
|---|---|---|
| smartmontools / `smartctl.exe` 7.5 | Bundled standalone subprocess used for ATA/SAT requests | GPL-2.0-or-later; full license and corresponding source archive in `licenses/smartmontools-GPL-2.txt` and `licenses/smartmontools-7.5.tar.gz`. Upstream [7.5 release](https://github.com/smartmontools/smartmontools/releases/tag/RELEASE_7_5). The binary and source archive are checked against pinned SHA-256 values in `build.py`. |
| PyInstaller 6.22.3 | Build tool and executable bootloader | GPL-2.0-or-later with the PyInstaller bootloader exception; full notice in `licenses/PyInstaller-COPYING.txt`. See the [versioned upstream license](https://github.com/pyinstaller/pyinstaller/blob/v6.22.3/COPYING.txt). |
| Python 3.14.10 | Runtime bundled in the executable and isolated helper | PSF License Version 2 and bundled license stack in `licenses/Python-LICENSE.txt`; see [Python 3.14 licensing](https://docs.python.org/3.14/license.html). |
| Tcl/Tk 9.0.4 | tkinter runtime bundled in the executable | License terms in `licenses/Tcl-license.terms`, `licenses/Tk-license.terms`, and `licenses/Tcl-Tk-license.terms`; upstream source tags are [Tcl](https://github.com/tcltk/tcl/tree/core-9-0-4) and [Tk](https://github.com/tcltk/tk/tree/core-9-0-4). |
| Pillow 13.0.0 | Build-only dependency used to generate the icon; not bundled in the application | MIT-CMU; license copy in `build-licenses/Pillow-LICENSE.txt`. |
| altgraph 0.17.5; pefile 2024.8.26; setuptools 84.2.1 | Build/test dependency closure recorded in `requirements-build-lock.txt`; not bundled as runtime application libraries | MIT. Their license metadata is in the pinned Python package distributions. |
| packaging 26.3 | Build/test dependency; not bundled as a runtime application library | Apache-2.0 OR BSD-2-Clause. |
| pywin32-ctypes 0.2.3 | Build/test dependency; not bundled as a runtime application library | BSD-3-Clause. |
| PyInstaller-hooks-contrib 2026.9 | Build/test hooks; not bundled as runtime application libraries | Contains Apache-2.0 and GPL-2.0 licensed components; see the package metadata in its pinned distribution. |

The bundled smartctl is a separate executable process, not merged into the Python control source. Its GPL terms are not replaced by the project's MIT license. The complete corresponding smartmontools source release and GPL text are included so recipients of the EXE receive the source and notices with the distribution.

The disk icon is drawn by this project from simple geometric shapes. Pillow is used only during icon generation and is not a runtime dependency.
