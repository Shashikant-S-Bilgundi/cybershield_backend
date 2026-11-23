# Windows version of build.sh: builds the Linux agent into agent\dist. Needs Go 1.22+ (https://go.dev/dl/).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$version = if ($env:VERSION) { $env:VERSION } else { "1.1.0" }
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:CGO_ENABLED = "0"; $env:GOOS = "linux"
foreach ($arch in "amd64", "arm64") {
  $env:GOARCH = $arch
  go build -trimpath -ldflags "-s -w -X main.version=$version" -o "dist/shieldops-agent-linux-$arch" .
}
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
$lines = Get-ChildItem dist/shieldops-agent-linux-* | ForEach-Object { "{0}  {1}" -f (Get-FileHash $_ -Algorithm SHA256).Hash.ToLower(), $_.Name }
Set-Content -Path dist/SHA256SUMS -Value $lines -NoNewline:$false
Write-Host "built version $version"; Get-Content dist/SHA256SUMS