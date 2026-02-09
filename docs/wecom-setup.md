# 企业微信（WeCom）自建应用（wecom-app）接入教程

## 前置条件

- 企业微信管理员账号
- `myclaw` 已编译（`make build`）
- 一个可公网访问的回调 URL（生产建议 HTTPS）
- 服务器公网 IP（需要配置企业微信可信 IP）

> 说明：myclaw 只实现渠道协议与业务逻辑；公网入口、证书、域名和反向代理由部署方自行配置。

## 协议说明（当前仅支持这一种）

当前 `wecom-app` 通道实现的是 **企业微信自建应用回调模式**。

回调特点：

- URL 校验：`GET` + `msg_signature/timestamp/nonce/echostr`
- 消息推送：`POST`，支持 XML/JSON 加密包（核心字段 `Encrypt/encrypt`）
- 入站解密后支持文本消息解析（JSON `text`、XML `MsgType=text`）
- 出站通过企业微信 API 主动发送：`gettoken` + `message/send`（支持 `text` 与 `markdown`）

## 能力边界

当前支持：

- 入站消息：文本（JSON/XML）
- 出站消息：`text` / `markdown` 主动发送（`touser`）
- `allowFrom` 白名单控制（未配置或空数组时默认放行）
- `msgid` 去重
- 回调签名校验 + 加解密
- access token 缓存与刷新

当前不支持：

- 群聊策略控制（当前按私聊主路径实现）
- 模板卡片
- 流式回复
- 复杂事件处理

## 第一步：创建企业微信自建应用

1. 登录企业微信管理后台
2. 进入「应用管理」→「自建」→「创建应用」
3. 创建后记录以下字段：
   - `AgentId`
   - `Secret`（即 `corpSecret`）
4. 在「我的企业」页面记录 `企业 ID`（即 `corpId`）

## 第二步：配置接收消息服务器

在应用详情页「接收消息」配置：

- URL：`https://your-domain.com/wecom-app`（或你的自定义 `webhookPath`）
- Token：与你配置文件一致
- EncodingAESKey：与你配置文件一致

保存时平台会发起 URL 验证请求，myclaw 会自动处理。

## 第三步：配置可信 IP（必须）

在应用详情页「企业可信 IP」中添加你的服务器公网出口 IP。

> 不加白名单会导致主动发送 API 调用失败（常见是权限或 IP 相关错误）。

## 第四步：配置 myclaw

编辑 `~/.myclaw/config.json`：

```json
{
  "channels": {
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

### 配置项说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `enabled` | bool | 是否启用 WeCom App 通道 |
| `webhookPath` | string | 回调路径，默认 `/wecom-app` |
| `token` | string | 回调签名 Token |
| `encodingAESKey` | string | 回调加解密密钥（43 位） |
| `receiveId` | string | 可选，启用严格接收方 ID 校验 |
| `corpId` | string | 企业 ID（用于获取 access token） |
| `corpSecret` | string | 应用 Secret |
| `agentId` | int | 应用 AgentId |
| `apiBaseUrl` | string | 可选 API 网关地址（默认 `https://qyapi.weixin.qq.com`） |
| `port` | int | 回调服务端口（默认 9886） |
| `allowFrom` | []string | 可选白名单；未配置或空数组时默认接收所有用户 |

### 环境变量（可选覆盖）

```bash
export MYCLAW_WECOM_APP_TOKEN="your-token"
export MYCLAW_WECOM_APP_ENCODING_AES_KEY="your-43-char-encoding-aes-key"
export MYCLAW_WECOM_APP_RECEIVE_ID="optional-receive-id"
export MYCLAW_WECOM_APP_CORP_ID="wwxxxxxxxx"
export MYCLAW_WECOM_APP_CORP_SECRET="your-corp-secret"
export MYCLAW_WECOM_APP_AGENT_ID="1000002"
export MYCLAW_WECOM_APP_API_BASE_URL=""
```

## 第五步：启动并验证

```bash
make gateway
```

日志出现如下信息表示通道已启动：

```text
[wecom-app] callback server listening on :9886/wecom-app
[gateway] channels started: [wecom-app]
```

然后在企业微信里给自建应用发一条文本消息，观察网关是否回包。

## 关键限制与风险

- `allowFrom` 行为是“默认放行”：
  - 未配置或 `[]`：接收所有入站消息
  - 配置非空列表：仅接收列表中的用户
- 主动发送依赖应用凭据与 IP 白名单：
  - `corpId/corpSecret/agentId` 任一缺失，发送直接失败
  - 出口 IP 未加入可信 IP，发送会失败
- 出站内容当前统一按字节截断到 2048（避免触发内容超限）
- 不要把 `token/encodingAESKey/corpSecret` 提交到仓库