@echo off
echo === Testing the webhook using a pure Python script inside the container ===
docker exec attense_app python /app/test_webhook_local.py
echo.
echo === Server Logs ===
docker logs --tail 20 attense_app
echo.
pause
