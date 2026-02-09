package channel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/stellarlinkco/myclaw/internal/bus"
	"github.com/stellarlinkco/myclaw/internal/config"
)

const wecomChannelName = "wecom-app"

const (
	wecomDefaultPort        = 9886
	wecomDefaultMsgCacheTTL = 5 * time.Minute
	wecomDefaultMsgCacheGC  = 1 * time.Minute
	wecomTextMaxBytes       = 2048
	wecomMarkdownMaxBytes   = 2048
	wecomSendMaxRetries     = 3
)

const (
	wecomMsgTypeText     = "text"
	wecomMsgTypeMarkdown = "markdown"
)

type WeComClient interface {
	SendMessage(ctx context.Context, msg bus.OutboundMessage) error
	Close()
}

type WeComClientFactory func(cfg config.WeComAppConfig) WeComClient

type defaultWeComClient struct {
	httpClient *http.Client
	cfg        config.WeComAppConfig

	tokenMu        sync.Mutex
	accessToken    string
	accessTokenExp time.Time
}

type weComTokenResponse struct {
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type weComSendResponse struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type weComAPIError struct {
	Code int
	Msg  string
}

func (e *weComAPIError) Error() string {
	return fmt.Sprintf("wecom-app api error: %d %s", e.Code, e.Msg)
}

func (e *weComAPIError) IsRetryable() bool {
	switch e.Code {
	case -1, 6000, 40014, 42001:
		return true
	default:
		return false
	}
}

type weComHTTPStatusError struct {
	Code     int
	Body     string
	Endpoint string
}

func (e *weComHTTPStatusError) Error() string {
	if e.Endpoint == "" {
		return fmt.Sprintf("wecom-app http status %d: %s", e.Code, e.Body)
	}
	return fmt.Sprintf("wecom-app %s status %d: %s", e.Endpoint, e.Code, e.Body)
}

func newDefaultWeComClient(cfg config.WeComAppConfig) WeComClient {
	return &defaultWeComClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cfg:        cfg,
	}
}

func (c *defaultWeComClient) Close() {}

func (c *defaultWeComClient) SendMessage(ctx context.Context, msg bus.OutboundMessage) error {
	toUser := strings.TrimSpace(msg.ChatID)
	if toUser == "" {
		return fmt.Errorf("wecom-app chat id is required")
	}

	msgType := resolveWeComOutboundMsgType(msg)
	maxBytes := wecomTextMaxBytes
	if msgType == wecomMsgTypeMarkdown {
		maxBytes = wecomMarkdownMaxBytes
	}

	content := truncateUTF8ByByteLimit(msg.Content, maxBytes)
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("wecom-app message content is empty")
	}

	return c.sendWithRetry(ctx, toUser, content, msgType)
}

func (c *defaultWeComClient) sendWithRetry(ctx context.Context, toUser, content, msgType string) error {
	var lastErr error
	for attempt := 1; attempt <= wecomSendMaxRetries; attempt++ {
		err := c.sendOnce(ctx, toUser, content, msgType)
		if err == nil {
			return nil
		}

		lastErr = err
		if !c.shouldRetry(err) || attempt == wecomSendMaxRetries {
			return err
		}

		var apiErr *weComAPIError
		if errors.As(err, &apiErr) && (apiErr.Code == 40014 || apiErr.Code == 42001) {
			c.clearAccessTokenCache()
		}

		backoff := time.Duration(attempt*attempt) * 100 * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}

	return lastErr
}

func (c *defaultWeComClient) shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var apiErr *weComAPIError
	if errors.As(err, &apiErr) {
		return apiErr.IsRetryable()
	}

	var statusErr *weComHTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Code >= 500 || statusErr.Code == http.StatusTooManyRequests
	}

	return true
}

func (c *defaultWeComClient) sendOnce(ctx context.Context, toUser, content, msgType string) error {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return err
	}

	payload := map[string]any{
		"touser":  toUser,
		"msgtype": msgType,
		"agentid": c.cfg.AgentID,
	}

	switch msgType {
	case wecomMsgTypeMarkdown:
		payload["markdown"] = map[string]string{"content": content}
	default:
		payload["text"] = map[string]string{"content": content}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal wecom-app send payload: %w", err)
	}

	sendURL := c.apiBaseURL() + "/cgi-bin/message/send?access_token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create wecom-app send request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send wecom-app message: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &weComHTTPStatusError{
			Code:     resp.StatusCode,
			Body:     strings.TrimSpace(string(raw)),
			Endpoint: "message/send",
		}
	}

	var result weComSendResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode wecom-app send response: %w", err)
	}
	if result.ErrCode != 0 {
		return &weComAPIError{Code: result.ErrCode, Msg: result.ErrMsg}
	}

	return nil
}

func (c *defaultWeComClient) getAccessToken(ctx context.Context) (string, error) {
	now := time.Now()
	c.tokenMu.Lock()
	if c.accessToken != "" && now.Before(c.accessTokenExp) {
		token := c.accessToken
		c.tokenMu.Unlock()
		return token, nil
	}
	c.tokenMu.Unlock()

	corpID := strings.TrimSpace(c.cfg.CorpID)
	corpSecret := strings.TrimSpace(c.cfg.CorpSecret)
	if corpID == "" || corpSecret == "" {
		return "", fmt.Errorf("wecom-app corpId and corpSecret are required")
	}

	tokenURL := fmt.Sprintf(
		"%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		c.apiBaseURL(),
		url.QueryEscape(corpID),
		url.QueryEscape(corpSecret),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("create wecom-app gettoken request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request wecom-app gettoken: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &weComHTTPStatusError{
			Code:     resp.StatusCode,
			Body:     strings.TrimSpace(string(raw)),
			Endpoint: "gettoken",
		}
	}

	var result weComTokenResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("decode wecom-app gettoken response: %w", err)
	}
	if result.ErrCode != 0 {
		return "", &weComAPIError{Code: result.ErrCode, Msg: result.ErrMsg}
	}
	if strings.TrimSpace(result.AccessToken) == "" {
		return "", fmt.Errorf("wecom-app gettoken returned empty access_token")
	}

	ttlSeconds := result.ExpiresIn
	if ttlSeconds <= 0 {
		ttlSeconds = 7200
	}
	expireAt := time.Now().Add(time.Duration(ttlSeconds-300) * time.Second)
	if ttlSeconds <= 300 {
		expireAt = time.Now().Add(time.Duration(ttlSeconds) * time.Second)
	}

	c.tokenMu.Lock()
	c.accessToken = result.AccessToken
	c.accessTokenExp = expireAt
	c.tokenMu.Unlock()

	return result.AccessToken, nil
}

func (c *defaultWeComClient) clearAccessTokenCache() {
	c.tokenMu.Lock()
	c.accessToken = ""
	c.accessTokenExp = time.Time{}
	c.tokenMu.Unlock()
}

func (c *defaultWeComClient) apiBaseURL() string {
	base := strings.TrimSpace(c.cfg.APIBaseURL)
	if base == "" {
		base = "https://qyapi.weixin.qq.com"
	}
	return strings.TrimRight(base, "/")
}

func truncateUTF8ByByteLimit(text string, maxBytes int) string {
	if maxBytes <= 0 || len([]byte(text)) <= maxBytes {
		return text
	}
	runes := []rune(text)
	bytesCount := 0
	for i, r := range runes {
		runeBytes := utf8.RuneLen(r)
		if runeBytes < 0 {
			runeBytes = 1
		}
		if bytesCount+runeBytes > maxBytes {
			return string(runes[:i])
		}
		bytesCount += runeBytes
	}
	return text
}

func resolveWeComOutboundMsgType(msg bus.OutboundMessage) string {
	if msg.Metadata == nil {
		return wecomMsgTypeText
	}

	for _, key := range []string{"wecom_msgtype", "msgtype"} {
		raw, ok := msg.Metadata[key]
		if !ok {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", raw)))
		switch value {
		case wecomMsgTypeMarkdown, "md":
			return wecomMsgTypeMarkdown
		case wecomMsgTypeText:
			return wecomMsgTypeText
		}
	}

	return wecomMsgTypeText
}

type weComMsgCache struct {
	mu     sync.Mutex
	items  map[string]time.Time
	ttl    time.Duration
	lastGC time.Time
}

func newWeComMsgCache(ttl time.Duration) *weComMsgCache {
	if ttl <= 0 {
		ttl = wecomDefaultMsgCacheTTL
	}
	return &weComMsgCache{
		items: make(map[string]time.Time),
		ttl:   ttl,
	}
}

func (c *weComMsgCache) Seen(key string) bool {
	if key == "" {
		return false
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if exp, ok := c.items[key]; ok {
		if now.Before(exp) {
			return true
		}
		delete(c.items, key)
	}

	c.items[key] = now.Add(c.ttl)
	c.gcLocked(now)

	return false
}

func (c *weComMsgCache) gcLocked(now time.Time) {
	if c.lastGC.IsZero() || now.Sub(c.lastGC) >= wecomDefaultMsgCacheGC {
		for messageID, exp := range c.items {
			if now.After(exp) {
				delete(c.items, messageID)
			}
		}
		c.lastGC = now
	}
}

type WeComChannel struct {
	BaseChannel
	cfg              config.WeComAppConfig
	server           *http.Server
	cancel           context.CancelFunc
	client           WeComClient
	clientFactory    WeComClientFactory
	allowlistEnabled bool
	msgCache         *weComMsgCache
	receiveID        string
	webhookPath      string
}

var defaultWeComClientFactory WeComClientFactory = func(cfg config.WeComAppConfig) WeComClient {
	return newDefaultWeComClient(cfg)
}

func NewWeComChannel(cfg config.WeComAppConfig, b *bus.MessageBus) (*WeComChannel, error) {
	return NewWeComChannelWithFactory(cfg, b, defaultWeComClientFactory)
}

func NewWeComChannelWithFactory(cfg config.WeComAppConfig, b *bus.MessageBus, factory WeComClientFactory) (*WeComChannel, error) {
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf("wecom-app token is required")
	}
	if len(strings.TrimSpace(cfg.EncodingAESKey)) != 43 {
		return nil, fmt.Errorf("wecom-app encodingAESKey must be 43 chars")
	}
	if strings.TrimSpace(cfg.CorpID) == "" {
		return nil, fmt.Errorf("wecom-app corpId is required")
	}
	if strings.TrimSpace(cfg.CorpSecret) == "" {
		return nil, fmt.Errorf("wecom-app corpSecret is required")
	}
	if cfg.AgentID <= 0 {
		return nil, fmt.Errorf("wecom-app agentId is required")
	}

	if factory == nil {
		factory = defaultWeComClientFactory
	}

	ch := &WeComChannel{
		BaseChannel:      NewBaseChannel(wecomChannelName, b, cfg.AllowFrom),
		cfg:              cfg,
		clientFactory:    factory,
		allowlistEnabled: len(cfg.AllowFrom) > 0,
		msgCache:         newWeComMsgCache(wecomDefaultMsgCacheTTL),
		receiveID:        strings.TrimSpace(cfg.ReceiveID),
		webhookPath:      normalizeWeComWebhookPath(cfg.WebhookPath),
	}

	return ch, nil
}

func normalizeWeComWebhookPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/wecom-app"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if len(trimmed) > 1 {
		trimmed = strings.TrimRight(trimmed, "/")
	}
	return trimmed
}

func (w *WeComChannel) Start(ctx context.Context) error {
	ctx, w.cancel = context.WithCancel(ctx)
	w.client = w.clientFactory(w.cfg)

	port := w.cfg.Port
	if port == 0 {
		port = wecomDefaultPort
	}

	mux := http.NewServeMux()
	mux.HandleFunc(w.webhookPath, w.handleCallback)

	w.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		log.Printf("[wecom-app] callback server listening on :%d%s", port, w.webhookPath)
		if err := w.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[wecom-app] server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = w.server.Close()
	}()

	return nil
}

func (w *WeComChannel) Stop() error {
	if w.cancel != nil {
		w.cancel()
	}
	if w.server != nil {
		_ = w.server.Close()
	}
	if w.client != nil {
		w.client.Close()
	}
	log.Printf("[wecom-app] stopped")
	return nil
}

func (w *WeComChannel) Send(msg bus.OutboundMessage) error {
	if w.client == nil {
		return fmt.Errorf("wecom-app client not initialized")
	}
	if strings.TrimSpace(msg.ChatID) == "" {
		return fmt.Errorf("wecom-app chat id is required")
	}
	return w.client.SendMessage(context.Background(), msg)
}

type weComEncryptedEnvelope struct {
	Encrypt string `json:"-"`
}

func (e *weComEncryptedEnvelope) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, key := range []string{"encrypt", "Encrypt"} {
		if v, ok := raw[key]; ok {
			return json.Unmarshal(v, &e.Encrypt)
		}
	}
	return nil
}

func (e weComEncryptedEnvelope) CipherText() string {
	return strings.TrimSpace(e.Encrypt)
}

type weComXMLEnvelope struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      string   `xml:"Encrypt"`
	MsgSignature string   `xml:"MsgSignature"`
	TimeStamp    string   `xml:"TimeStamp"`
	Nonce        string   `xml:"Nonce"`
}

type weComFrom struct {
	UserID string `json:"userid"`
}

type weComText struct {
	Content string `json:"content"`
}

type weComMixedItem struct {
	MsgType string    `json:"msgtype"`
	Text    weComText `json:"text"`
}

type weComMixed struct {
	MsgItem []weComMixedItem `json:"msg_item"`
}

type weComVoice struct {
	Content string `json:"content"`
}

type weComInboundMessage struct {
	MsgID       string     `json:"msgid"`
	MsgIDAlt    string     `json:"MsgId"`
	AIBotID     string     `json:"aibotid"`
	ChatID      string     `json:"chatid"`
	ChatIDAlt   string     `json:"ChatId"`
	ChatType    string     `json:"chattype"`
	ChatTypeAlt string     `json:"ChatType"`
	From        weComFrom  `json:"from"`
	FromUserID  string     `json:"fromuserid"`
	FromName    string     `json:"FromUserName"`
	MsgType     string     `json:"msgtype"`
	MsgTypeAlt  string     `json:"MsgType"`
	Text        weComText  `json:"text"`
	Content     string     `json:"Content"`
	Mixed       weComMixed `json:"mixed"`
	Voice       weComVoice `json:"voice"`
	Recognition string     `json:"Recognition"`
}

type weComXMLPlainMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   string   `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
	Content      string   `xml:"Content"`
	MsgID        string   `xml:"MsgId"`
	AgentID      string   `xml:"AgentID"`
	ChatID       string   `xml:"ChatId"`
	ChatType     string   `xml:"ChatType"`
	Recognition  string   `xml:"Recognition"`
}

type weComReplyEnvelope struct {
	Encrypt         string `json:"encrypt"`
	MsgSignature    string `json:"msgsignature"`
	MsgSignatureAlt string `json:"msg_signature,omitempty"`
	Timestamp       string `json:"timestamp"`
	Nonce           string `json:"nonce"`
}

func (w *WeComChannel) handleCallback(resp http.ResponseWriter, req *http.Request) {
	sig := resolveWeComSignatureParam(req)
	timestamp := req.URL.Query().Get("timestamp")
	nonce := req.URL.Query().Get("nonce")

	if sig == "" || timestamp == "" || nonce == "" {
		http.Error(resp, "missing signature params", http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodGet:
		w.verifyCallbackURL(resp, req, sig, timestamp, nonce)
	case http.MethodPost:
		w.handleIncomingMessage(resp, req, sig, timestamp, nonce)
	default:
		http.Error(resp, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func resolveWeComSignatureParam(req *http.Request) string {
	query := req.URL.Query()
	for _, key := range []string{"msg_signature", "msgsignature", "signature"} {
		if value := strings.TrimSpace(query.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func (w *WeComChannel) verifyCallbackURL(resp http.ResponseWriter, req *http.Request, sig, timestamp, nonce string) {
	echostr := req.URL.Query().Get("echostr")
	if echostr == "" {
		http.Error(resp, "missing echostr", http.StatusBadRequest)
		return
	}

	if w.signature(timestamp, nonce, echostr) != sig {
		http.Error(resp, "invalid signature", http.StatusUnauthorized)
		return
	}

	plaintext, _, err := w.decrypt(echostr)
	if err != nil {
		http.Error(resp, "decrypt echostr failed", http.StatusBadRequest)
		return
	}

	resp.WriteHeader(http.StatusOK)
	_, _ = resp.Write([]byte(plaintext))
}

func (w *WeComChannel) handleIncomingMessage(resp http.ResponseWriter, req *http.Request, querySig, queryTimestamp, queryNonce string) {
	req.Body = http.MaxBytesReader(resp, req.Body, 1<<20)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, "read body failed", http.StatusBadRequest)
		return
	}

	encrypt, bodySig, bodyTimestamp, bodyNonce, err := parseWeComEncryptedBody(body)
	if err != nil {
		http.Error(resp, "invalid payload", http.StatusBadRequest)
		return
	}
	if encrypt == "" {
		http.Error(resp, "missing encrypt field", http.StatusBadRequest)
		return
	}

	sig := querySig
	if bodySig != "" {
		sig = bodySig
	}
	timestamp := queryTimestamp
	if bodyTimestamp != "" {
		timestamp = bodyTimestamp
	}
	nonce := queryNonce
	if bodyNonce != "" {
		nonce = bodyNonce
	}

	if w.signature(timestamp, nonce, encrypt) != sig {
		http.Error(resp, "invalid signature", http.StatusUnauthorized)
		return
	}

	plaintext, receiveID, err := w.decrypt(encrypt)
	if err != nil {
		http.Error(resp, "decrypt message failed", http.StatusBadRequest)
		return
	}

	replyBody, err := w.buildEncryptedReply(timestamp, nonce, receiveID, "success")
	if err != nil {
		http.Error(resp, "encrypt reply failed", http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusOK)
	_, _ = resp.Write(replyBody)

	go w.processDecryptedMessage(plaintext)
}

func parseWeComEncryptedBody(body []byte) (encrypt, sig, timestamp, nonce string, err error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", "", "", "", fmt.Errorf("empty payload")
	}

	if strings.HasPrefix(trimmed, "<") {
		var envelope weComXMLEnvelope
		if unmarshalErr := xml.Unmarshal([]byte(trimmed), &envelope); unmarshalErr != nil {
			return "", "", "", "", unmarshalErr
		}
		return strings.TrimSpace(envelope.Encrypt), strings.TrimSpace(envelope.MsgSignature), strings.TrimSpace(envelope.TimeStamp), strings.TrimSpace(envelope.Nonce), nil
	}

	var envelope weComEncryptedEnvelope
	if unmarshalErr := json.Unmarshal([]byte(trimmed), &envelope); unmarshalErr != nil {
		return "", "", "", "", unmarshalErr
	}
	return envelope.CipherText(), "", "", "", nil
}

func (w *WeComChannel) buildEncryptedReply(timestamp, nonce, receiveID string, payload any) ([]byte, error) {
	if payload == nil {
		payload = map[string]any{}
	}

	plainJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal reply payload: %w", err)
	}

	encrypt, err := w.encrypt(string(plainJSON), receiveID)
	if err != nil {
		return nil, fmt.Errorf("encrypt reply payload: %w", err)
	}

	msgSig := w.signature(timestamp, nonce, encrypt)
	reply := weComReplyEnvelope{
		Encrypt:         encrypt,
		MsgSignature:    msgSig,
		MsgSignatureAlt: msgSig,
		Timestamp:       timestamp,
		Nonce:           nonce,
	}

	body, err := json.Marshal(reply)
	if err != nil {
		return nil, fmt.Errorf("marshal reply envelope: %w", err)
	}

	return body, nil
}

func (w *WeComChannel) processDecryptedMessage(plaintext string) {
	message, err := parseWeComInboundMessage(plaintext)
	if err != nil {
		log.Printf("[wecom-app] parse plaintext message error: %v", err)
		return
	}

	senderID := w.resolveSenderID(message)
	if senderID == "" {
		return
	}

	if !w.allowMessageFrom(senderID) {
		log.Printf("[wecom-app] rejected message from %s", senderID)
		return
	}

	messageID := message.normalizedMsgID()
	if messageID != "" && w.msgCache.Seen(messageID) {
		log.Printf("[wecom-app] duplicate message dropped: %s", messageID)
		return
	}

	chatID := w.resolveChatID(message, senderID)
	if chatID == "" {
		return
	}

	content := extractWeComContent(message)
	if content == "" {
		return
	}

	w.bus.Inbound <- bus.InboundMessage{
		Channel:   wecomChannelName,
		SenderID:  senderID,
		ChatID:    chatID,
		Content:   content,
		Timestamp: time.Now(),
		Metadata: map[string]any{
			"msg_id":    messageID,
			"aibot_id":  strings.TrimSpace(message.AIBotID),
			"chat_id":   strings.TrimSpace(message.normalizedChatID()),
			"chat_type": strings.TrimSpace(message.normalizedChatType()),
			"msg_type":  strings.TrimSpace(message.normalizedMsgType()),
		},
	}
}

func parseWeComInboundMessage(plaintext string) (weComInboundMessage, error) {
	trimmed := strings.TrimSpace(plaintext)
	if trimmed == "" {
		return weComInboundMessage{}, fmt.Errorf("empty plaintext")
	}

	if strings.HasPrefix(trimmed, "<") {
		var xmlMessage weComXMLPlainMessage
		if err := xml.Unmarshal([]byte(trimmed), &xmlMessage); err != nil {
			return weComInboundMessage{}, err
		}

		message := weComInboundMessage{
			MsgID:      strings.TrimSpace(xmlMessage.MsgID),
			FromUserID: strings.TrimSpace(xmlMessage.FromUserName),
			FromName:   strings.TrimSpace(xmlMessage.FromUserName),
			ChatID:     strings.TrimSpace(xmlMessage.ChatID),
			ChatType:   strings.TrimSpace(xmlMessage.ChatType),
			MsgType:    strings.TrimSpace(xmlMessage.MsgType),
			Text: weComText{
				Content: strings.TrimSpace(xmlMessage.Content),
			},
			Voice: weComVoice{
				Content: strings.TrimSpace(xmlMessage.Recognition),
			},
			Recognition: strings.TrimSpace(xmlMessage.Recognition),
			Content:     strings.TrimSpace(xmlMessage.Content),
		}
		message.normalize()
		return message, nil
	}

	var message weComInboundMessage
	if err := json.Unmarshal([]byte(trimmed), &message); err != nil {
		return weComInboundMessage{}, err
	}
	message.normalize()

	return message, nil
}

func (m *weComInboundMessage) normalize() {
	if strings.TrimSpace(m.MsgID) == "" {
		m.MsgID = strings.TrimSpace(m.MsgIDAlt)
	}
	if strings.TrimSpace(m.ChatID) == "" {
		m.ChatID = strings.TrimSpace(m.ChatIDAlt)
	}
	if strings.TrimSpace(m.ChatType) == "" {
		m.ChatType = strings.TrimSpace(m.ChatTypeAlt)
	}
	if strings.TrimSpace(m.MsgType) == "" {
		m.MsgType = strings.TrimSpace(m.MsgTypeAlt)
	}
	if strings.TrimSpace(m.From.UserID) == "" {
		if from := strings.TrimSpace(m.FromUserID); from != "" {
			m.From.UserID = from
		} else if from := strings.TrimSpace(m.FromName); from != "" {
			m.From.UserID = from
		}
	}
}

func (m weComInboundMessage) normalizedMsgID() string {
	return strings.TrimSpace(m.MsgID)
}

func (m weComInboundMessage) normalizedChatID() string {
	return strings.TrimSpace(m.ChatID)
}

func (m weComInboundMessage) normalizedChatType() string {
	return strings.TrimSpace(m.ChatType)
}

func (m weComInboundMessage) normalizedMsgType() string {
	return strings.ToLower(strings.TrimSpace(m.MsgType))
}

func (w *WeComChannel) resolveSenderID(message weComInboundMessage) string {
	senderID := strings.TrimSpace(message.From.UserID)
	if senderID != "" {
		return senderID
	}
	if senderID = strings.TrimSpace(message.FromUserID); senderID != "" {
		return senderID
	}
	return strings.TrimSpace(message.FromName)
}

func (w *WeComChannel) resolveChatID(message weComInboundMessage, senderID string) string {
	if strings.EqualFold(message.normalizedChatType(), "group") {
		if chatID := message.normalizedChatID(); chatID != "" {
			return chatID
		}
	}
	if chatID := message.normalizedChatID(); chatID != "" {
		return chatID
	}
	return senderID
}

func extractWeComContent(message weComInboundMessage) string {
	switch message.normalizedMsgType() {
	case "text":
		if content := strings.TrimSpace(message.Text.Content); content != "" {
			return content
		}
		return strings.TrimSpace(message.Content)
	case "voice":
		if content := strings.TrimSpace(message.Voice.Content); content != "" {
			return content
		}
		return strings.TrimSpace(message.Recognition)
	case "mixed":
		parts := make([]string, 0, len(message.Mixed.MsgItem))
		for _, item := range message.Mixed.MsgItem {
			if !strings.EqualFold(strings.TrimSpace(item.MsgType), "text") {
				continue
			}
			if text := strings.TrimSpace(item.Text.Content); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.TrimSpace(strings.Join(parts, "\n"))
	case "event":
		return ""
	default:
		log.Printf("[wecom-app] unsupported message type: %s", strings.TrimSpace(message.MsgType))
		return ""
	}
}

func (w *WeComChannel) allowMessageFrom(senderID string) bool {
	if !w.allowlistEnabled {
		return true
	}
	return w.IsAllowed(senderID)
}

func (w *WeComChannel) signature(timestamp, nonce, data string) string {
	parts := []string{w.cfg.Token, timestamp, nonce, data}
	sort.Strings(parts)
	joined := strings.Join(parts, "")
	sum := sha1.Sum([]byte(joined))
	return fmt.Sprintf("%x", sum)
}

func (w *WeComChannel) decrypt(encrypted string) (string, string, error) {
	aesKey, err := decodeWeComAESKey(w.cfg.EncodingAESKey)
	if err != nil {
		return "", "", fmt.Errorf("decode aes key: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", "", fmt.Errorf("base64 decode encrypted data: %w", err)
	}
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return "", "", fmt.Errorf("invalid encrypted block size")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", "", fmt.Errorf("new aes cipher: %w", err)
	}

	plain := make([]byte, len(raw))
	iv := aesKey[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plain, raw)

	plain, err = pkcs7Unpad(plain, 32)
	if err != nil {
		return "", "", fmt.Errorf("pkcs7 unpad: %w", err)
	}

	if len(plain) < 20 {
		return "", "", fmt.Errorf("plaintext too short")
	}

	msgLen := int(binary.BigEndian.Uint32(plain[16:20]))
	if msgLen < 0 || 20+msgLen > len(plain) {
		return "", "", fmt.Errorf("invalid msg length")
	}

	msg := plain[20 : 20+msgLen]
	receiveID := string(plain[20+msgLen:])
	expectedReceiveID := strings.TrimSpace(w.receiveID)
	if expectedReceiveID != "" && receiveID != expectedReceiveID {
		return "", "", fmt.Errorf("receive id mismatch")
	}

	return string(msg), receiveID, nil
}

func (w *WeComChannel) encrypt(plaintext, receiveID string) (string, error) {
	aesKey, err := decodeWeComAESKey(w.cfg.EncodingAESKey)
	if err != nil {
		return "", fmt.Errorf("decode aes key: %w", err)
	}

	random16 := make([]byte, 16)
	if _, err := rand.Read(random16); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	msg := []byte(plaintext)
	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(msg)))

	raw := make([]byte, 0, len(random16)+4+len(msg)+len(receiveID))
	raw = append(raw, random16...)
	raw = append(raw, msgLen...)
	raw = append(raw, msg...)
	raw = append(raw, []byte(receiveID)...)

	padded := pkcs7Pad(raw, 32)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("new aes cipher: %w", err)
	}

	cipherData := make([]byte, len(padded))
	iv := aesKey[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherData, padded)

	return base64.StdEncoding.EncodeToString(cipherData), nil
}

func decodeWeComAESKey(encodingAESKey string) ([]byte, error) {
	trimmed := strings.TrimSpace(encodingAESKey)
	if trimmed == "" {
		return nil, fmt.Errorf("empty encodingAESKey")
	}

	withPadding := trimmed
	if !strings.HasSuffix(withPadding, "=") {
		withPadding += "="
	}

	aesKey, err := base64.StdEncoding.DecodeString(withPadding)
	if err != nil {
		return nil, err
	}
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("invalid aes key length: %d", len(aesKey))
	}

	return aesKey, nil
}

func pkcs7Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	if padding == 0 {
		padding = blockSize
	}
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding length")
	}

	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}

	return data[:len(data)-padLen], nil
}
