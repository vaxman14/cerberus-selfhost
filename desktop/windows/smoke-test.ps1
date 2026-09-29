param([Parameter(Mandatory = $true)][string]$StageRoot)

$ErrorActionPreference = "Stop"
$Runtime = Join-Path $StageRoot "runtime"
$Tools = Join-Path $Runtime "tools"
$Scratch = Join-Path $env:TEMP ("cerberus-smoke-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $Scratch | Out-Null
$Processes = @()

function Free-Port {
    $Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $Listener.Start()
    $Port = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
    $Listener.Stop()
    return $Port
}

function Wait-Http([string]$Url, [string]$Name, [int]$Seconds = 60) {
    $Deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try {
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
            if ($Response.StatusCode -eq 200) { return $Response }
        } catch { Start-Sleep -Milliseconds 500 }
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw "$Name did not become healthy at $Url"
}

try {
    Write-Host "Proving packaged command-line runtimes"
    & (Join-Path $Tools "nuclei.exe") -version
    if ($LASTEXITCODE -ne 0) { throw "Nuclei version probe failed" }
    & (Join-Path $Tools "python/python.exe") (Join-Path $Tools "sqlmap/sqlmap.py") --version
    if ($LASTEXITCODE -ne 0) { throw "sqlmap version probe failed" }
    & (Join-Path $Tools "node/node.exe") (Join-Path $Tools "node-packages/node_modules/lighthouse/cli/index.js") --version
    if ($LASTEXITCODE -ne 0) { throw "Lighthouse version probe failed" }
    $env:PATH = "$(Join-Path $Tools 'node');$env:PATH"
    & (Join-Path $Tools "node-packages/node_modules/.bin/codex.cmd") --version
    if ($LASTEXITCODE -ne 0) { throw "Codex CLI version probe failed" }
    & (Join-Path $Tools "jre/bin/java.exe") -version
    if ($LASTEXITCODE -ne 0) { throw "Java version probe failed" }

    $ToolsToken = Join-Path $Scratch "tools_token"
    $ZapKeyFile = Join-Path $Scratch "zap_api_key"
    $MasterKey = Join-Path $Scratch "master_key"
    $ZapKey = ([Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N"))
    ([Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N")) | Set-Content $ToolsToken -NoNewline
    $ZapKey | Set-Content $ZapKeyFile -NoNewline
    ([Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N")) | Set-Content $MasterKey -NoNewline

    $ZapPort = Free-Port
    $ZapHome = Join-Path $Scratch "zap"
    New-Item -ItemType Directory -Force $ZapHome | Out-Null
    $Zap = Start-Process (Join-Path $Tools "jre/bin/java.exe") -PassThru -WindowStyle Hidden `
        -ArgumentList @(
            "-Xmx1536m", "-Djava.awt.headless=true", "-jar", (Join-Path $Tools "zap/zap-2.17.0.jar"),
            "-daemon", "-silent", "-host", "127.0.0.1", "-port", "$ZapPort", "-dir", $ZapHome,
            "-config", "api.disablekey=false", "-config", "api.key=$ZapKey",
            "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.regex=false"
        )
    $Processes += $Zap
    Wait-Http "http://127.0.0.1:$ZapPort/JSON/core/view/version/?apikey=$ZapKey" "ZAP" 90 | Out-Null

    $ToolsPort = Free-Port
    $env:CERBERUS_TOOLS_HOST = "127.0.0.1"
    $env:CERBERUS_TOOLS_PORT = "$ToolsPort"
    $env:CERBERUS_TOOLS_TOKEN_FILE = $ToolsToken
    $env:CERBERUS_LIGHTHOUSE_BIN = Join-Path $Tools "node/node.exe"
    $env:CERBERUS_LIGHTHOUSE_SCRIPT = Join-Path $Tools "node-packages/node_modules/lighthouse/cli/index.js"
    $env:CERBERUS_NUCLEI_BIN = Join-Path $Tools "nuclei.exe"
    $env:CERBERUS_NUCLEI_TEMPLATES = Join-Path $Tools "nuclei-templates"
    $env:CERBERUS_PYTHON_BIN = Join-Path $Tools "python/python.exe"
    $env:CERBERUS_SQLMAP_PATH = Join-Path $Tools "sqlmap/sqlmap.py"
    $Worker = Start-Process (Join-Path $Runtime "cerberus-tools/cerberus-tools.exe") -PassThru -WindowStyle Hidden
    $Processes += $Worker
    Wait-Http "http://127.0.0.1:$ToolsPort/health" "scanner worker" 30 | Out-Null

    $ApiPort = Free-Port
    $env:CERBERUS_API_HOST = "127.0.0.1"
    $env:CERBERUS_API_PORT = "$ApiPort"
    $env:CERBERUS_AUTH_MODE = "local"
    $env:CERBERUS_DB_PATH = Join-Path $Scratch "cerberus.db"
    $env:CERBERUS_MASTER_KEY_FILE = $MasterKey
    $env:CERBERUS_TOOLS_URL = "http://127.0.0.1:$ToolsPort"
    $env:CERBERUS_ENABLE_ACTIVE_SCANS = "true"
    $env:ZAP_API = "http://127.0.0.1:$ZapPort"
    $env:ZAP_API_KEY_FILE = $ZapKeyFile
    $Api = Start-Process (Join-Path $Runtime "cerberus-api/cerberus-api.exe") -PassThru -WindowStyle Hidden
    $Processes += $Api
    Wait-Http "http://127.0.0.1:$ApiPort/health" "Cerberus API" 30 | Out-Null
    $Console = Wait-Http "http://127.0.0.1:$ApiPort/" "Cerberus console" 10
    if ($Console.Content -notmatch "CERBERUS") { throw "Packaged console was not served" }

    Write-Host "Complete Windows runtime smoke test passed"
} finally {
    for ($Index = $Processes.Count - 1; $Index -ge 0; $Index--) {
        $Process = $Processes[$Index]
        if ($null -ne $Process -and -not $Process.HasExited) {
            taskkill /PID $Process.Id /T /F | Out-Null
        }
    }
    if (Test-Path $Scratch) { Remove-Item $Scratch -Recurse -Force }
}
