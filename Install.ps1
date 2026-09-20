param([Parameter(Mandatory=$true)][string]$GameDirectory)
$ErrorActionPreference = 'Stop'
if (!(Test-Path (Join-Path $GameDirectory 'mgsvtpp.exe'))) { throw 'Select the folder containing mgsvtpp.exe.' }
if (Get-Process mgsvtpp -ErrorAction SilentlyContinue) { throw 'Exit MGSV before installing.' }
$dll = Join-Path $PSScriptRoot 'dist\plugins\choomaudio.dll'
if (!(Test-Path $dll)) { throw 'Run BUILD.cmd successfully first.' }
$plugins = Join-Path $GameDirectory 'plugins'
New-Item -ItemType Directory -Force -Path $plugins | Out-Null
Copy-Item $dll (Join-Path $plugins 'choomaudio.dll') -Force
$config = Join-Path $plugins 'choomaudio.lua'
if (!(Test-Path $config)) { Copy-Item (Join-Path $PSScriptRoot 'dist\plugins\choomaudio.lua') $config }
$modules = Join-Path $GameDirectory 'mod\modules'
New-Item -ItemType Directory -Force -Path $modules | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'dist\mod\modules\ChoomAudio_Core.lua') (Join-Path $modules 'ChoomAudio_Core.lua') -Force
Write-Host "Installed to $plugins and $modules (existing plugin config preserved)."
Write-Host 'Infinite Heaven loads the installed ChoomAudio_Core.lua module on startup.'
