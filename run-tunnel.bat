@echo off
setlocal

set "CLOUDFLARED=%USERPROFILE%\Downloads\cloudflared-windows-amd64.exe"

if not exist "%CLOUDFLARED%" (
    echo Cannot find cloudflared at "%CLOUDFLARED%".
    echo Download the Windows AMD64 executable from Cloudflare and try again.
    pause
    exit /b 1
)

echo Opening a temporary public tunnel to http://127.0.0.1:8000
echo Keep this window open while others use the website.
"%CLOUDFLARED%" tunnel --url http://127.0.0.1:8000
pause
