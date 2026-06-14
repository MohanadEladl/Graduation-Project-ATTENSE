# PowerShell script to register a Wazuh responder in Cortex
# Edit variables below then run in PowerShell: .\register_wazuh_responder.ps1

$CORTEX_URL = 'http://localhost:9001'
$CORTEX_API_KEY = 'REPLACE_WITH_CORTEX_API_KEY'
$WAZUH_API_URL = 'http://wazuh-manager:55000'
$WAZUH_USER = 'REPLACE_WAZUH_USER'
$WAZUH_PASS = 'REPLACE_WAZUH_PASS'

# Adjust path if your Cortex API uses a different endpoint
$apiPath = '/api/responder'

$payload = @{
  name = 'wazuh-block-ip'
  description = 'Block IP via Wazuh active-response (dry-run default)'
  type = 'wazuh'
  enabled = $true
  config = @{
    wazuh_api_url = $WAZUH_API_URL
    wazuh_user = $WAZUH_USER
    wazuh_password = $WAZUH_PASS
    active_response = 'block_ip'
    args = @('{{case_id}}','{{data.target_ip}}','dry-run')
  }
} | ConvertTo-Json -Depth 6

$headers = @{ Authorization = "Bearer $CORTEX_API_KEY"; 'Content-Type' = 'application/json' }

Write-Host "Registering responder at $CORTEX_URL$apiPath"
$response = Invoke-RestMethod -Uri ($CORTEX_URL + $apiPath) -Method Post -Headers $headers -Body $payload
$response | ConvertTo-Json -Depth 6

Write-Host 'Done. Check Cortex UI or API to confirm the responder was created.'
