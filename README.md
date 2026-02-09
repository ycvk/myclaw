# myclaw

Personal AI assistant built on [agentsdk-go](https://github.com/cexll/agentsdk-go).

## Features

- **Agent Mode** - Run a single message or interactive REPL
- **Gateway** - Full orchestration: channels + cron + heartbeat
- **Telegram Channel** - Receive and send messages via Telegram bot
- **Feishu Channel** - Receive and send messages via Feishu (Lark) bot
- **WeCom App Channel** - Receive inbound messages and actively send text/markdown replies via WeCom self-built app API
- **Multi-Provider** - Support for Anthropic and OpenAI models
- **Cron Jobs** - Scheduled tasks with JSON persistence
- **Heartbeat** - Periodic tasks from HEARTBEAT.md

## Quick Start

### 1) Setup

```bash
make setup
make onboard
```

### 2) Configure API key

Set `MYCLAW_API_KEY` (or edit `~/.myclaw/config.json`).

### 3) Run

```bash
# agent mode
make agent

# gateway mode
make gateway
```

## Commands

| Command | Description |
|---------|-------------|
| `make agent` | Run agent REPL |
| `make gateway` | Start gateway mode |
| `make onboard` | Initialize config and workspace |
| `make status` | Show runtime status |
| `make setup` | Interactive setup wizard |
| `make tunnel` | Start cloudflared tunnel for Feishu webhook |
| `make test` | Run tests |

## Architecture

Data Flow (Gateway Mode):

```text
Telegram/Feishu/WeCom App ──► Channel ──► Bus.Inbound ──► processLoop
                                                       │
                                                       ▼
                                                Runtime.Run()
                                                       │
                                                       ▼
                                       Bus.Outbound ──► Channel ──► Telegram/Feishu/WeCom App
```

## Project Structure

```text
cmd/myclaw/          CLI entry point (agent, gateway, onboard, status)
internal/
  bus/               Message bus (inbound/outbound channels)
  channel/           Channel interface + Telegram + Feishu + WeCom App implementations
  config/            Configuration loading (JSON + env vars)
  cron/              Cron job scheduling with JSON persistence
  gateway/           Gateway orchestration (bus + runtime + channels)
  heartbeat/         HEARTBEAT.md scheduler
  memory/            Workspace memory store
docs/
  telegram-setup.md  Telegram bot setup guide
  feishu-setup.md    Feishu bot setup guide
  wecom-setup.md     WeCom App setup guide
scripts/
  setup.sh           Interactive config generator
workspace/
  AGENTS.md          Runtime behavior prompt
  SOUL.md            Runtime personality prompt
  HEARTBEAT.md       Scheduled heartbeat prompt
```

## Configuration

Run `make setup` for interactive config, or copy `config.example.json` to `~/.myclaw/config.json`.

Example channel config:

```json
{
  "channels": {
    "telegram": {
      "enabled": true,
      "token": "123456:telegram-token",
      "allowFrom": []
    },
    "feishu": {
      "enabled": true,
      "appId": "cli_xxx",
      "appSecret": "your-app-secret",
      "verificationToken": "your-verification-token",
      "port": 9876,
      "allowFrom": []
    },
    "wecom-app": {
      "enabled": true,
      "webhookPath": "/wecom-app",
      "token": "your-token",
      "encodingAESKey": "your-43-char-encoding-aes-key",
      "receiveId": "",
      "corpId": "wwxxxxxxxx",
      "corpSecret": "your-corp-secret",
      "agentId": 1000002,
      "apiBaseUrl": "",
      "port": 9886,
      "allowFrom": ["zhangsan"]
    }
  }
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `MYCLAW_API_KEY` | Anthropic/OpenAI API key |
| `MYCLAW_BASE_URL` | Optional model API base URL |
| `MYCLAW_TELEGRAM_TOKEN` | Telegram bot token |
| `MYCLAW_FEISHU_APP_ID` | Feishu app ID |
| `MYCLAW_FEISHU_APP_SECRET` | Feishu app secret |
| `MYCLAW_WECOM_APP_TOKEN` | WeCom App callback token |
| `MYCLAW_WECOM_APP_ENCODING_AES_KEY` | WeCom App callback EncodingAESKey |
| `MYCLAW_WECOM_APP_RECEIVE_ID` | Optional receive ID for strict decrypt validation |
| `MYCLAW_WECOM_APP_CORP_ID` | WeCom corpId |
| `MYCLAW_WECOM_APP_CORP_SECRET` | WeCom corpSecret |
| `MYCLAW_WECOM_APP_AGENT_ID` | WeCom agentId |
| `MYCLAW_WECOM_APP_API_BASE_URL` | Optional WeCom API base URL |

> Prefer environment variables over config files for sensitive values like API keys.

## Channel Setup

### Telegram

See `docs/telegram-setup.md`.

### Feishu

See `docs/feishu-setup.md`.

### WeCom App (Self-built app)

See `docs/wecom-setup.md`.

Quick steps:

1. Create a WeCom self-built app and get `corpId/corpSecret/agentId`
2. Configure callback URL: `https://your-domain/wecom-app`
3. Set `token` and `encodingAESKey` in both WeCom console and myclaw config
4. Configure `corpId/corpSecret/agentId` for active send
5. Add server public IP to WeCom trusted IP list
6. Run `make gateway`

WeCom App notes:

- Outbound supports active `text` and `markdown` messages through `cgi-bin/message/send`
- Access token is cached and refreshed automatically
- Outbound content is truncated at 2048 bytes for safety (current unified limit)
- Current implementation is private-chat oriented

## Docker Deployment

### Build and Run

```bash
docker build -t myclaw .

docker run -d \
  -e MYCLAW_API_KEY=your-api-key \
  -e MYCLAW_TELEGRAM_TOKEN=your-token \
  -p 18790:18790 \
  -p 9876:9876 \
  -p 9886:9886 \
  -v myclaw-data:/root/.myclaw \
  myclaw
```

### Docker Compose

```bash
# Create .env from example
cp .env.example .env
# Edit .env with your credentials

# Start gateway
docker compose up -d

# Start with cloudflared tunnel (for Feishu webhook)
docker compose --profile tunnel up -d

# View logs
docker compose logs -f myclaw
```

### Cloudflared Tunnel

For Feishu webhooks, you need a public URL:

```bash
# Temporary tunnel (dev)
make tunnel

# Or via docker compose
docker compose --profile tunnel up -d
docker compose logs tunnel | grep trycloudflare
```

Set the output URL + `/feishu/webhook` as your Feishu event subscription URL.

## Security

- `~/.myclaw/config.json` is set to `chmod 600` (owner read/write only)
- `.gitignore` excludes `config.json`, `.env`, and workspace memory files
- Use environment variables for sensitive values in CI/CD and production
- Never commit real API keys or tokens to version control

## Testing

```bash
make test            # Run all tests
make test-race       # Run with race detection
make test-cover      # Run with coverage report
make lint            # Run golangci-lint
```

## License

MIT
