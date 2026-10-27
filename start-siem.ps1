$ErrorActionPreference = "Stop"

$root = "C:\Users\Prerana K Urs\OneDrive\Desktop\SIEM Login Threat & Anomaly Analyzer"
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"

Write-Host "Starting SIEM services..." -ForegroundColor Cyan

# Start Docker services only if they are not already running.
foreach ($name in @("siem-namenode", "siem-datanode", "siem-hive")) {
    $status = docker inspect --format '{{.State.Running}}' $name 2>$null

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Container $name was not found. Skipping it." -ForegroundColor Yellow
    }
    elseif ($status -ne "true") {
        Write-Host "Starting $name..."
        docker start $name
        if ($LASTEXITCODE -ne 0) {
            throw "Could not start $name. Check Docker Desktop."
        }
    }
    else {
        Write-Host "$name is already running."
    }
}

if (-not (Test-Path (Join-Path $backend "server.js"))) {
    throw "Backend server.js was not found."
}
if (-not (Test-Path (Join-Path $frontend "node_modules\vite\bin\vite.js"))) {
    throw "Vite is missing. Run npm install in the frontend folder."
}

# Open backend in its own PowerShell window.
$backendCommand = "Set-Location -LiteralPath '$backend'; node server.js"
Start-Process -FilePath "powershell.exe" -WorkingDirectory $backend -ArgumentList @(
    "-NoExit", "-Command", $backendCommand
)

# Open frontend in its own PowerShell window.
$frontendCommand = "Set-Location -LiteralPath '$frontend'; node '.\node_modules\vite\bin\vite.js'"
Start-Process -FilePath "powershell.exe" -WorkingDirectory $frontend -ArgumentList @(
    "-NoExit", "-Command", $frontendCommand
)

Write-Host ""
Write-Host "Startup commands launched." -ForegroundColor Green
Write-Host "Dashboard: http://localhost:5173"
Write-Host "API health: http://localhost:5000/api/health"
Write-Host "Keep the service windows open while using SIEM."
