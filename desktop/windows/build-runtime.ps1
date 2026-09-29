param(
    [string]$BuildRoot = (Join-Path $env:TEMP "cerberus-windows-build"),
    [string]$StageRoot = (Join-Path $env:TEMP "cerberus-windows-stage")
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Repository = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$Lock = Get-Content (Join-Path $PSScriptRoot "runtime.lock.json") -Raw | ConvertFrom-Json
$Downloads = Join-Path $BuildRoot "downloads"
$Sources = Join-Path $BuildRoot "sources"
$Runtime = Join-Path $StageRoot "runtime"
$Tools = Join-Path $Runtime "tools"

if (Test-Path $StageRoot) { Remove-Item $StageRoot -Recurse -Force }
New-Item -ItemType Directory -Force $Downloads, $Sources, $Runtime, $Tools, (Join-Path $BuildRoot "spec") | Out-Null

function Get-VerifiedFile([string]$Url, [string]$Sha256, [string]$Name) {
    $Destination = Join-Path $Downloads $Name
    if (-not (Test-Path $Destination) -or
        (Get-FileHash $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Sha256.ToLowerInvariant()) {
        Invoke-WebRequest -Uri $Url -OutFile $Destination
    }
    $Actual = (Get-FileHash $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Sha256.ToLowerInvariant()) {
        throw "SHA-256 mismatch for $Name. Expected $Sha256, received $Actual."
    }
    return $Destination
}

function Expand-FlatZip([string]$Archive, [string]$Destination) {
    $Scratch = Join-Path $BuildRoot ("expand-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force $Scratch | Out-Null
    Expand-Archive -Path $Archive -DestinationPath $Scratch -Force
    $Children = @(Get-ChildItem $Scratch)
    $Source = if ($Children.Count -eq 1 -and $Children[0].PSIsContainer) { $Children[0].FullName } else { $Scratch }
    if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }
    New-Item -ItemType Directory -Force $Destination | Out-Null
    Copy-Item (Join-Path $Source "*") $Destination -Recurse -Force
    Remove-Item $Scratch -Recurse -Force
}

function Checkout-Pinned([string]$Url, [string]$Commit, [string]$Destination) {
    if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }
    git init --quiet $Destination
    git -C $Destination remote add origin $Url
    git -C $Destination fetch --quiet --depth 1 origin $Commit
    git -C $Destination checkout --quiet --detach FETCH_HEAD
    $Actual = (git -C $Destination rev-parse HEAD).Trim()
    if ($Actual -ne $Commit) { throw "Pinned checkout mismatch for $Url" }
}

Write-Host "Building Cerberus Python sidecars"
$Venv = Join-Path $BuildRoot "venv"
if (Test-Path $Venv) { Remove-Item $Venv -Recurse -Force }
python -m venv $Venv
$VenvPython = Join-Path $Venv "Scripts/python.exe"
& $VenvPython -m pip install --disable-pip-version-check --requirement (Join-Path $Repository "requirements.txt") "pyinstaller==$($Lock.pyinstaller.version)"
& $VenvPython -m PyInstaller --noconfirm --clean --onedir --console `
    --name cerberus-api --paths $Repository `
    --collect-data tldextract --collect-data certifi `
    --add-data "$(Join-Path $Repository 'console');console" `
    --distpath $Runtime --workpath (Join-Path $BuildRoot "pyinstaller/api") `
    --specpath (Join-Path $BuildRoot "spec") `
    (Join-Path $PSScriptRoot "python/api_entry.py")
& $VenvPython -m PyInstaller --noconfirm --clean --onedir --console `
    --name cerberus-tools --paths $Repository `
    --distpath $Runtime --workpath (Join-Path $BuildRoot "pyinstaller/tools") `
    --specpath (Join-Path $BuildRoot "spec") `
    (Join-Path $PSScriptRoot "python/tools_entry.py")
& $VenvPython -m PyInstaller --noconfirm --clean --onedir --console `
    --name cerberus-userctl --paths $Repository `
    --distpath $Runtime --workpath (Join-Path $BuildRoot "pyinstaller/userctl") `
    --specpath (Join-Path $BuildRoot "spec") `
    (Join-Path $PSScriptRoot "python/userctl_entry.py")
& $VenvPython -m PyInstaller --noconfirm --clean --onedir --console `
    --name cerberus-backupctl --paths $Repository `
    --distpath $Runtime --workpath (Join-Path $BuildRoot "pyinstaller/backupctl") `
    --specpath (Join-Path $BuildRoot "spec") `
    (Join-Path $PSScriptRoot "python/backupctl_entry.py")

Write-Host "Installing pinned Python, Node, Java, and ZAP runtimes"
$PythonArchive = Get-VerifiedFile $Lock.python.url $Lock.python.sha256 "python-embed.zip"
Expand-FlatZip $PythonArchive (Join-Path $Tools "python")
$NodeArchive = Get-VerifiedFile $Lock.node.url $Lock.node.sha256 "node.zip"
Expand-FlatZip $NodeArchive (Join-Path $Tools "node")
$JavaArchive = Get-VerifiedFile $Lock.java.url $Lock.java.sha256 "jre.zip"
Expand-FlatZip $JavaArchive (Join-Path $Tools "jre")
$ZapArchive = Get-VerifiedFile $Lock.zap.url $Lock.zap.sha256 "zap.zip"
Expand-FlatZip $ZapArchive (Join-Path $Tools "zap")

Write-Host "Installing locked Lighthouse $($Lock.lighthouse.version) and Codex CLI $($Lock.codex.version)"
$NodePackages = Join-Path $Tools "node-packages"
New-Item -ItemType Directory -Force $NodePackages | Out-Null
Copy-Item (Join-Path $PSScriptRoot "node-runtime/package.json") $NodePackages
Copy-Item (Join-Path $PSScriptRoot "node-runtime/package-lock.json") $NodePackages
& (Join-Path $Tools "node/npm.cmd") ci --prefix $NodePackages --omit=dev --ignore-scripts --no-audit --no-fund

Write-Host "Building pinned Nuclei"
$NucleiSource = Join-Path $Sources "nuclei"
Checkout-Pinned "https://github.com/projectdiscovery/nuclei.git" $Lock.nuclei.commit $NucleiSource
Push-Location $NucleiSource
try {
    go get github.com/go-git/go-git/v5@v5.19.2 golang.org/x/crypto@v0.55.0 golang.org/x/mod@v0.40.0 google.golang.org/grpc@v1.83.2
    go mod tidy
    $env:CGO_ENABLED = "0"
    go build -trimpath -ldflags="-s -w" -o (Join-Path $Tools "nuclei.exe") ./cmd/nuclei
} finally { Pop-Location }

Write-Host "Installing pinned Nuclei templates and sqlmap"
Checkout-Pinned "https://github.com/projectdiscovery/nuclei-templates.git" $Lock.nucleiTemplates.commit (Join-Path $Tools "nuclei-templates")
Remove-Item (Join-Path $Tools "nuclei-templates/.git") -Recurse -Force
Checkout-Pinned "https://github.com/sqlmapproject/sqlmap.git" $Lock.sqlmap.commit (Join-Path $Tools "sqlmap")
Remove-Item (Join-Path $Tools "sqlmap/.git") -Recurse -Force

Write-Host "Collecting third-party license notices"
$Licenses = Join-Path $StageRoot "licenses"
New-Item -ItemType Directory -Force $Licenses | Out-Null
Copy-Item (Join-Path $Repository "LICENSE") (Join-Path $Licenses "Cerberus-AGPL-3.0.txt")
Copy-Item (Join-Path $PSScriptRoot "THIRD_PARTY_NOTICES.md") $Licenses
Copy-Item (Join-Path $Tools "python/LICENSE.txt") (Join-Path $Licenses "Python-LICENSE.txt")
Copy-Item (Join-Path $Tools "node/LICENSE") (Join-Path $Licenses "Node-LICENSE.txt")
Copy-Item (Join-Path $Tools "node-packages/node_modules/lighthouse/LICENSE") (Join-Path $Licenses "Lighthouse-LICENSE.txt")
$CodexLicense = Get-VerifiedFile $Lock.codex.licenseUrl $Lock.codex.licenseSha256 "Codex-LICENSE.txt"
Copy-Item $CodexLicense (Join-Path $Licenses "Codex-LICENSE.txt")
Copy-Item (Join-Path $NucleiSource "LICENSE.md") (Join-Path $Licenses "Nuclei-LICENSE.txt")
Copy-Item (Join-Path $Tools "nuclei-templates/LICENSE.md") (Join-Path $Licenses "Nuclei-Templates-LICENSE.txt")
Copy-Item (Join-Path $Tools "sqlmap/LICENSE") (Join-Path $Licenses "sqlmap-LICENSE.txt")
Copy-Item (Join-Path $Tools "jre/legal") (Join-Path $Licenses "Temurin-legal") -Recurse
$ZapLicense = Get-ChildItem (Join-Path $Tools "zap") -Recurse -File |
    Where-Object { $_.Name -match '^LICENSE(?:\.txt)?$' } | Select-Object -First 1
if ($ZapLicense) { Copy-Item $ZapLicense.FullName (Join-Path $Licenses "ZAP-LICENSE.txt") }

Write-Host "Publishing Windows desktop shell"
dotnet publish (Join-Path $PSScriptRoot "Cerberus.Desktop/Cerberus.Desktop.csproj") `
    --configuration Release --runtime win-x64 --self-contained true `
    -p:PublishSingleFile=false -p:DebugType=None -p:DebugSymbols=false `
    --output $StageRoot

$Manifest = @{
    cerberusVersion = "0.2.2"
    generatedAt = [DateTimeOffset]::UtcNow.ToString("O")
    runtime = $Lock
} | ConvertTo-Json -Depth 8
$Manifest | Set-Content (Join-Path $StageRoot "runtime-manifest.json") -Encoding UTF8

Write-Host "Windows stage created at $StageRoot"
