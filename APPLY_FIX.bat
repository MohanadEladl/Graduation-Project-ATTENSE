@echo off
echo === Rebuilding and Restarting Attense App Container ===
cd /d "%~dp0"
docker-compose up -d --build --force-recreate attense-app
echo.
echo === Waiting 12 seconds for the server to boot up ===
timeout /t 12 /nobreak
echo.
echo === Sending a test FalsePositive webhook ===
docker exec attense_app curl -s -X POST http://localhost:8010/internal/webhook/hive -H "Content-Type: application/json" -d "{\"objectType\":\"Case\",\"operation\":\"Update\",\"object\":{\"status\":\"Resolved\",\"resolutionStatus\":\"FalsePositive\",\"tags\":[\"attense:incident-wazuh-test-001\"]}}"
echo.
echo === Showing the server logs (Look for 'alert_denied') ===
docker logs --tail 20 attense_app
echo.
pause
