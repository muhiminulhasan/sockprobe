@echo off
REM Example usage script for SockProbe on Windows

echo === SockProbe Usage Examples ===

echo 1. Scanning a private network range:
echo    sockprobe --targets 192.168.1.0/24 --ports 1080 ^
echo      --attest "authorized to test 192.168.1.0/24" --out results.jsonl
echo.

echo 2. Scanning with username/password authentication:
echo    sockprobe --targets 10.0.0.0/24 --ports 1080 ^
echo      --user myuser --password mypass ^
echo      --attest "authorized to test 10.0.0.0/24" --out results.jsonl
echo.

echo 3. Scanning with verification (SOCKS4/4a detection):
echo    sockprobe --targets 172.16.0.0/16 --ports 1080 ^
echo      --verify 172.16.0.100:80 ^
echo      --attest "authorized to test 172.16.0.0/16" --out results.jsonl
echo.

echo 4. Scanning with custom blocklist:
echo    sockprobe --targets 192.168.0.0/16 --ports 1080 ^
echo      --attest "authorized to test 192.168.0.0/16" --out results.jsonl ^
echo      --blocklist-file my_blocklist.yaml
echo.

echo 5. Scanning public networks (requires explicit authorization):
echo    sockprobe --targets 203.0.113.0/24 --ports 1080 ^
echo      --attest "authorized to test 203.0.113.0/24" --out results.jsonl ^
echo      --enable-public --allowlist 203.0.113.0/24
echo.

echo === Processing Results ===
echo View all SOCKS5 proxies:
echo   type results.jsonl ^| jq "select(.protocol == \"socks5\")"
echo.
echo Count proxies by type:
echo   type results.jsonl ^| jq -r ".protocol" ^| sort ^| uniq -c
echo.
echo Find verified proxies:
echo   findstr /c:"\"verified\":true" results.jsonl