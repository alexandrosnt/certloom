# Runs docs/getting-started/windows-iis.md end to end on a disposable Windows
# Server (the guides workflow): certloomd, PostgreSQL and Pebble on the same
# host stand in for the certloom server and Let's Encrypt. Needs an elevated
# shell, IIS, and certloomd.exe, certloom.exe and certloom-agent.exe in $Bin.
param(
    [Parameter(Mandatory)] [string] $Bin,
    [string] $PebbleVersion = "v2.10.3"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$work = Join-Path $env:RUNNER_TEMP "guide"
New-Item -ItemType Directory -Force $work | Out-Null

function Invoke-Checked {
    param([string] $File, [string[]] $Arguments, [string] $InputText)
    if ($InputText) { $out = $InputText | & $File @Arguments 2>&1 } else { $out = & $File @Arguments 2>&1 }
    $text = ($out | Out-String)
    Write-Host "> $File $($Arguments -join ' ')`n$text"
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
    return $text
}

function Wait-Until {
    param([string] $What, [int] $Seconds, [scriptblock] $Test)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Test) { return }
        Start-Sleep -Seconds 2
    }
    throw "timed out waiting for $What"
}

# ---- Stand-in certloom server --------------------------------------------

$pg = Get-Service postgresql* | Select-Object -First 1
Set-Service $pg.Name -StartupType Manual
Start-Service $pg.Name
$psql = Join-Path $env:PGBIN "psql.exe"
$env:PGPASSWORD = "root"
Invoke-Checked $psql @("-U", "postgres", "-tAc", "SELECT version()") | Out-Null
Invoke-Checked $psql @("-U", "postgres", "-c", "CREATE ROLE certloom_owner LOGIN CREATEROLE PASSWORD 'owner-test'") | Out-Null
Invoke-Checked $psql @("-U", "postgres", "-c", "CREATE DATABASE certloom OWNER certloom_owner") | Out-Null
$env:CERTLOOM_MIGRATE_DATABASE_URL = "postgres://certloom_owner:owner-test@127.0.0.1:5432/certloom?sslmode=disable"
Invoke-Checked "$Bin\certloomd.exe" @("migrate") | Out-Null
$env:PGPASSWORD = "owner-test"
Invoke-Checked $psql @("-U", "certloom_owner", "-d", "certloom", "-c", "ALTER ROLE certloom_app LOGIN PASSWORD 'app-test'") | Out-Null

# Pebble, with its test certificates from the same tag.
$pebbleZip = Join-Path $work "pebble.zip"
Invoke-WebRequest "https://github.com/letsencrypt/pebble/releases/download/$PebbleVersion/pebble-windows-amd64.zip" -OutFile $pebbleZip
Expand-Archive $pebbleZip (Join-Path $work "pebble") -Force
$pebbleExe = Get-ChildItem (Join-Path $work "pebble") -Recurse -Filter pebble.exe | Select-Object -First 1
foreach ($f in "localhost/cert.pem", "localhost/key.pem", "pebble.minica.pem") {
    $dest = Join-Path $work ($f -replace "/", "-")
    Invoke-WebRequest "https://raw.githubusercontent.com/letsencrypt/pebble/$PebbleVersion/test/certs/$f" -OutFile $dest
}
@"
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
 "certificate": "$($work -replace '\\','/')/localhost-cert.pem", "privateKey": "$($work -replace '\\','/')/localhost-key.pem",
 "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false,
 "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
 "profiles": {"default": {"description": "default", "validityPeriod": 7776000}}}}
"@ | Set-Content -Encoding ascii (Join-Path $work "pebble.json")
$env:PEBBLE_VA_NOSLEEP = "1"
Start-Process $pebbleExe.FullName -ArgumentList "-config", (Join-Path $work "pebble.json") `
    -RedirectStandardOutput (Join-Path $work "pebble.log") -RedirectStandardError (Join-Path $work "pebble.err") -NoNewWindow
$minica = Join-Path $work "pebble.minica.pem"

# certloomd itself.
$openssl = "C:\Program Files\Git\usr\bin\openssl.exe"
$tlsCert = Join-Path $work "server.crt"
$tlsKey = Join-Path $work "server.key"
Invoke-Checked $openssl @("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", $tlsKey, "-out", $tlsCert) | Out-Null
$kek = Join-Path $work "kek"
& "$Bin\certloomd.exe" gen-kek | Set-Content -Encoding ascii -NoNewline $kek
$env:CERTLOOM_DATABASE_URL = "postgres://certloom_app:app-test@127.0.0.1:5432/certloom?sslmode=disable"
$env:CERTLOOM_LISTEN = "127.0.0.1:8443"
$env:CERTLOOM_TLS_CERT = $tlsCert
$env:CERTLOOM_TLS_KEY = $tlsKey
$env:CERTLOOM_KEK_FILE = $kek
$env:CERTLOOM_AGENT_LISTEN = "127.0.0.1:8444"
$env:CERTLOOM_AGENT_SERVER_NAMES = "localhost"
$env:CERTLOOM_AGENT_PUBLIC_URL = "https://localhost:8444"
$env:CERTLOOM_ACME_CA_FILE = $minica
Start-Process "$Bin\certloomd.exe" -ArgumentList "serve" `
    -RedirectStandardOutput (Join-Path $work "certloomd.log") -RedirectStandardError (Join-Path $work "certloomd.err") -NoNewWindow
Wait-Until "certloomd" 60 { (Test-NetConnection localhost -Port 8443 -WarningAction SilentlyContinue).TcpTestSucceeded }
$boot = Invoke-Checked "$Bin\certloomd.exe" @("bootstrap", "--org", "Guide")
$env:CERTLOOM_SERVER = "https://localhost:8443"
$env:CERTLOOM_CA_FILE = $tlsCert
$env:CERTLOOM_TOKEN = [regex]::Match($boot, "certloom_org_\S+").Value
$cli = "$Bin\certloom.exe"

# ---- The guide, on the IIS host ------------------------------------------

$name = "shop.guide.test"
Add-Content -Encoding ascii "$env:SystemRoot\System32\drivers\etc\hosts" "`n127.0.0.1 $name"

# Step 1: install the agent (here: the binary under test instead of the release zip).
$agentDir = "C:\Program Files\certloom-agent"
New-Item -ItemType Directory -Force $agentDir | Out-Null
Copy-Item "$Bin\certloom-agent.exe" $agentDir
$env:Path += ";$agentDir"
$agent = "certloom-agent"

# Step 2: the IIS site with its http and https bindings.
Import-Module WebAdministration
New-Item -ItemType Directory -Force C:\inetpub\shop | Out-Null
Set-Content C:\inetpub\shop\index.html "shop"
# The site exists with an unrelated binding; the guide adds the two it needs.
New-Website -Name Shop -PhysicalPath C:\inetpub\shop -Port 8088 | Out-Null
New-WebBinding -Name Shop -Protocol http  -Port 80  -HostHeader $name
New-WebBinding -Name Shop -Protocol https -Port 443 -HostHeader $name -SslFlags 1

# Step 3: agent config.
New-Item -ItemType Directory -Force C:\ProgramData\certloom-agent | Out-Null
@"
server: https://localhost:8444
state_dir: C:\ProgramData\certloom-agent\state
name: iis-01
acme_ca_file: $minica
targets:
  - name: shop
    type: iis
    site: Shop
    bindings: ["*:443:$name"]
    webroot: C:\inetpub\shop
    allowed_sans: [$name]
"@ | Set-Content -Encoding ascii C:\ProgramData\certloom-agent\config.yaml
Invoke-Checked $agent @("check-config") | Out-Null

# Step 4: enroll and start the service.
$tok = Invoke-Checked $cli @("agent", "token", "--name", "iis-01")
$token = [regex]::Match($tok, "certloomenr_\S+").Value
$hash = [regex]::Match($tok, "sha256:[0-9a-f]{64}").Value
Invoke-Checked $agent @("enroll", "--server", "https://localhost:8444", "--ca-hash", $hash, "--token-stdin") -InputText $token | Out-Null
Invoke-Checked $agent @("service", "install") | Out-Null
Invoke-Checked "sc.exe" @("start", "certloom-agent") | Out-Null
Wait-Until "agent heartbeat" 60 { (& $cli agent list 2>&1 | Out-String) -match "iis-01\s+active" }

# Step 5: issuer, endpoint, deployment, first certificate.
Invoke-Checked $cli @("issuer", "create", "letsencrypt", "--directory", "https://localhost:14000/dir", "--agree-tos") | Out-Null
Invoke-Checked $cli @("scope", "create", "web", "--allow-host", $name, "--allow-loopback") | Out-Null
Invoke-Checked $cli @("endpoint", "add", $name, "--scope", "web") | Out-Null
Invoke-Checked $cli @("lineage", "create", "shop") | Out-Null
$dep = Invoke-Checked $cli @("deployment", "create", "--lineage", "shop", "--agent", "iis-01", "--target", "shop",
    "--issuer", "letsencrypt", "--endpoint", $name, "--san", $name)
$depID = [regex]::Match($dep, "dep_[a-z0-9]+").Value

foreach ($round in 1, 2) {
    $run = Invoke-Checked $cli @("deployment", "renew", $depID)
    $runID = [regex]::Match($run, "run_[a-z0-9]+").Value
    Wait-Until "run $runID" 180 { (& $cli run show $runID 2>&1 | Out-String) -cmatch ": (VERIFIED|FAILED|ROLLED_BACK|CANCELLED)" }
    $show = Invoke-Checked $cli @("run", "show", $runID)
    if ($show -cnotmatch ": VERIFIED") { throw "renewal $round did not verify" }
}
Invoke-Checked $cli @("deployment", "list") | Out-Null
Get-ChildItem Cert:\LocalMachine\WebHosting | Format-Table Subject, Thumbprint, FriendlyName, NotAfter
& netsh http show sslcert hostnameport="${name}:443"
Write-Host "guide OK"
