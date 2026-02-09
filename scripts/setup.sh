#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${HOME}/.myclaw"
CONFIG_FILE="${CONFIG_DIR}/config.json"

echo "=== myclaw setup ==="
echo ""

# Check if config exists
if [ -f "$CONFIG_FILE" ]; then
    echo "Config already exists: $CONFIG_FILE"
    read -rp "Overwrite? [y/N] " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Provider
echo ""
echo "--- Provider ---"
read -rp "Provider type [anthropic/openai] (default: anthropic): " PROVIDER_TYPE
PROVIDER_TYPE="${PROVIDER_TYPE:-anthropic}"

read -rp "API Key: " API_KEY
read -rp "Base URL (leave empty for default): " BASE_URL

# Feishu
echo ""
echo "--- Feishu Channel ---"
read -rp "Enable Feishu? [y/N]: " FEISHU_ENABLED
if [[ "$FEISHU_ENABLED" =~ ^[Yy]$ ]]; then
    FEISHU_ENABLED="true"
    read -rp "App ID: " FEISHU_APP_ID
    read -rp "App Secret: " FEISHU_APP_SECRET
    read -rp "Verification Token (leave empty to skip): " FEISHU_VTOKEN
    read -rp "Webhook port (default: 9876): " FEISHU_PORT
    FEISHU_PORT="${FEISHU_PORT:-9876}"
else
    FEISHU_ENABLED="false"
    FEISHU_APP_ID=""
    FEISHU_APP_SECRET=""
    FEISHU_VTOKEN=""
    FEISHU_PORT="9876"
fi

# Telegram
echo ""
echo "--- Telegram Channel ---"
read -rp "Enable Telegram? [y/N]: " TG_ENABLED
if [[ "$TG_ENABLED" =~ ^[Yy]$ ]]; then
    TG_ENABLED="true"
    read -rp "Bot Token: " TG_TOKEN
else
    TG_ENABLED="false"
    TG_TOKEN=""
fi

# WeCom App (Self-built app)
echo ""
echo "--- WeCom App Channel (Self-built app) ---"
read -rp "Enable WeCom App? [y/N]: " WECOM_APP_ENABLED
if [[ "$WECOM_APP_ENABLED" =~ ^[Yy]$ ]]; then
    WECOM_APP_ENABLED="true"
    read -rp "Webhook path (default: /wecom-app): " WECOM_APP_WEBHOOK_PATH
    WECOM_APP_WEBHOOK_PATH="${WECOM_APP_WEBHOOK_PATH:-/wecom-app}"
    read -rp "Token: " WECOM_APP_TOKEN
    read -rp "EncodingAESKey (43 chars): " WECOM_APP_AES_KEY
    read -rp "ReceiveID (optional, leave empty to skip strict check): " WECOM_APP_RECEIVE_ID
    read -rp "CorpID: " WECOM_APP_CORP_ID
    read -rp "CorpSecret: " WECOM_APP_CORP_SECRET
    read -rp "AgentID (number): " WECOM_APP_AGENT_ID
    read -rp "API base URL (optional, default: https://qyapi.weixin.qq.com): " WECOM_APP_API_BASE_URL
    read -rp "Callback port (default: 9886): " WECOM_APP_PORT
    WECOM_APP_PORT="${WECOM_APP_PORT:-9886}"
else
    WECOM_APP_ENABLED="false"
    WECOM_APP_WEBHOOK_PATH="/wecom-app"
    WECOM_APP_TOKEN=""
    WECOM_APP_AES_KEY=""
    WECOM_APP_RECEIVE_ID=""
    WECOM_APP_CORP_ID=""
    WECOM_APP_CORP_SECRET=""
    WECOM_APP_AGENT_ID="0"
    WECOM_APP_API_BASE_URL=""
    WECOM_APP_PORT="9886"
fi

# Write config
mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_FILE" <<EOF_JSON
{
  "agent": {
    "workspace": "${HOME}/.myclaw/workspace",
    "model": "claude-sonnet-4-5-20250929",
    "maxTokens": 8192,
    "temperature": 0.7,
    "maxToolIterations": 20
  },
  "provider": {
    "type": "${PROVIDER_TYPE}",
    "apiKey": "${API_KEY}",
    "baseUrl": "${BASE_URL}"
  },
  "channels": {
    "telegram": {
      "enabled": ${TG_ENABLED},
      "token": "${TG_TOKEN}",
      "allowFrom": [],
      "proxy": ""
    },
    "feishu": {
      "enabled": ${FEISHU_ENABLED},
      "appId": "${FEISHU_APP_ID}",
      "appSecret": "${FEISHU_APP_SECRET}",
      "verificationToken": "${FEISHU_VTOKEN}",
      "encryptKey": "",
      "port": ${FEISHU_PORT},
      "allowFrom": []
    },
    "wecom-app": {
      "enabled": ${WECOM_APP_ENABLED},
      "webhookPath": "${WECOM_APP_WEBHOOK_PATH}",
      "token": "${WECOM_APP_TOKEN}",
      "encodingAESKey": "${WECOM_APP_AES_KEY}",
      "receiveId": "${WECOM_APP_RECEIVE_ID}",
      "corpId": "${WECOM_APP_CORP_ID}",
      "corpSecret": "${WECOM_APP_CORP_SECRET}",
      "agentId": ${WECOM_APP_AGENT_ID},
      "apiBaseUrl": "${WECOM_APP_API_BASE_URL}",
      "port": ${WECOM_APP_PORT},
      "allowFrom": []
    }
  },
  "tools": {
    "braveApiKey": "",
    "execTimeout": 60,
    "restrictToWorkspace": true
  },
  "gateway": {
    "host": "0.0.0.0",
    "port": 18790
  }
}
EOF_JSON

chmod 600 "$CONFIG_FILE"

echo ""
echo "Config written to: $CONFIG_FILE"
echo ""
echo "Next steps:"
echo "  make onboard    # Initialize workspace"
echo "  make gateway    # Start gateway"
if [ "$FEISHU_ENABLED" = "true" ]; then
    echo "  make tunnel     # Start cloudflared tunnel for Feishu webhook"
fi
if [ "$WECOM_APP_ENABLED" = "true" ]; then
    echo "  Configure callback URL to ${WECOM_APP_WEBHOOK_PATH}"
    echo "  Add server public IP to WeCom trusted IP list"
fi
echo ""
echo "Done."
