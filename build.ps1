param([ValidateSet('onedir','onefile')][string]$Mode='onedir')
$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$buildRoot = Join-Path $repo 'build'
$venv = Join-Path $buildRoot '.venv'
$python = Join-Path $venv 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
    py -3.14-64 -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw '无法创建 64 位构建环境。' }
}
if (-not (Test-Path -LiteralPath $python)) { throw '找不到构建环境中的 Python。' }
$bits = & $python -c "import struct; print(struct.calcsize('P') * 8)"
if ($LASTEXITCODE -ne 0 -or $bits.Trim() -ne '64') { throw '构建环境必须是 64 位 Python。' }
$version = & $python -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
if ($LASTEXITCODE -ne 0 -or $version.Trim() -ne '3.14.10') { throw '构建需要 Python 3.14.10。' }

& $python -m pip install --disable-pip-version-check -r (Join-Path $repo 'requirements-build-lock.txt')
if ($LASTEXITCODE -ne 0) { throw '安装固定版本构建依赖失败。' }
& $python (Join-Path $repo 'build.py') $Mode
if ($LASTEXITCODE -ne 0) { throw '构建失败。' }
