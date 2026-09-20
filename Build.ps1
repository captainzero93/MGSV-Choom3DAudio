$ErrorActionPreference = 'Stop'
try {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (!(Test-Path $vswhere)) { throw 'Install Visual Studio with Desktop development with C++ and a Windows SDK.' }
    $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (!$vs) { throw 'No Visual Studio C++ x64 tools found.' }
    $msbuild = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
    $toolset = Get-ChildItem (Join-Path $vs 'MSBuild\Microsoft\VC') -Directory -Recurse |
        Where-Object { $_.Parent.Name -eq 'PlatformToolsets' -and $_.FullName -match '\\Platforms\\x64\\' -and $_.Name -match '^v\d+$' } |
        Sort-Object { [int]($_.Name.Substring(1)) } -Descending | Select-Object -First 1
    if (!$toolset) { throw 'No x64 MSVC platform toolset found.' }
    Write-Host "Building ChoomAudio Release/x64 with $($toolset.Name)"
    & $msbuild (Join-Path $PSScriptRoot 'choomaudio.vcxproj') /t:Rebuild /m /nologo /p:Configuration=Release /p:Platform=x64 "/p:PlatformToolset=$($toolset.Name)"
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed ($LASTEXITCODE)." }
    $dll = Join-Path $PSScriptRoot 'dist\plugins\choomaudio.dll'
    $bytes = [IO.File]::ReadAllBytes($dll)
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    if ([BitConverter]::ToUInt32($bytes,$pe) -ne 0x4550 -or [BitConverter]::ToUInt16($bytes,$pe+4) -ne 0x8664) { throw 'Output is not an x64 PE DLL.' }
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    foreach ($marker in @('CHOOMAUDIO_PLUGIN_PORT_073_R1','luaopen_choomaudio','ChoomAudioVersion')) {
        if (!$text.Contains($marker)) { throw "Output missing $marker" }
    }
    # Stage the DLL, settings and IH loader in the installation layout.
    $dist = Join-Path $PSScriptRoot 'dist'
    $modules = Join-Path $dist 'mod\modules'
    New-Item -ItemType Directory -Force -Path $modules | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'packaging\choomaudio.lua') (Join-Path $dist 'plugins\choomaudio.lua') -Force
    Copy-Item (Join-Path $PSScriptRoot 'packaging\ChoomAudio_Core.lua') (Join-Path $modules 'ChoomAudio_Core.lua') -Force
    foreach ($leftover in @('choomaudio.exp','choomaudio.lib','choomaudio.pdb','choomaudio.ilk')) {
        Remove-Item (Join-Path $dist ('plugins\' + $leftover)) -Force -ErrorAction SilentlyContinue
    }
    $zip = Join-Path $PSScriptRoot 'ChoomAudio_plugin.zip'
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip
    Write-Host "Built: $dll"
    Get-FileHash $dll -Algorithm SHA256 | Format-List
    Write-Host 'Package layout:'
    Get-ChildItem $dist -Recurse -File | ForEach-Object { '  ' + $_.FullName.Substring($dist.Length + 1) }
    Write-Host "Ready: $zip"
    Write-Host 'Copy the contents of dist (mod + plugins) into the folder holding mgsvtpp.exe, or run Install.ps1 -GameDirectory "your game folder".'
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
