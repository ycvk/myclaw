package channel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stellarlinkco/myclaw/internal/bus"
	"github.com/stellarlinkco/myclaw/internal/config"
)

type mockWeComClient struct {
	sent []bus.OutboundMessage
	err  error
}

func (m *mockWeComClient) SendMessage(ctx context.Context, msg bus.OutboundMessage) error {
	m.sent = append(m.sent, msg)
	return m.err
}

func (m *mockWeComClient) Close() {}

func mockWeComClientFactory(client *mockWeComClient) WeComClientFactory {
	return func(cfg config.WeComAppConfig) WeComClient {
		return client
	}
}

func TestNewWeComChannel_Valid(t *testing.T) {
	b := bus.NewMessageBus(10)
	ch, err := NewWeComChannel(config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		ReceiveID:      "recv-id-1",
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	}, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch.Name() != "wecom-app" {
		t.Errorf("Name = %q, want wecom-app", ch.Name())
	}
}

func TestNewWeComChannel_MissingRequiredConfig(t *testing.T) {
	b := bus.NewMessageBus(10)
	_, err := NewWeComChannel(config.WeComAppConfig{}, b)
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestWeComChannel_Send_NilClient(t *testing.T) {
	b := bus.NewMessageBus(10)
	ch, _ := NewWeComChannelWithFactory(config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	}, b, nil)

	err := ch.Send(bus.OutboundMessage{ChatID: "zhangsan", Content: "hello"})
	if err == nil {
		t.Fatal("expected error when client is nil")
	}
}

func TestWeComCallback_VerifyURL_OK(t *testing.T) {
	ch, _ := newTestWeComChannel(t, config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		ReceiveID:      "recv-id-1",
		AllowFrom:      []string{"zhangsan"},
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	})

	timestamp := "1739000000"
	nonce := "nonce-1"
	echostr := testWeComEncrypt(t, ch.cfg.EncodingAESKey, ch.receiveID, "hello-challenge")
	signature := testWeComSignature(ch.cfg.Token, timestamp, nonce, echostr)

	req := httptest.NewRequest(http.MethodGet, "/wecom-app", nil)
	q := req.URL.Query()
	q.Set("msg_signature", signature)
	q.Set("timestamp", timestamp)
	q.Set("nonce", nonce)
	q.Set("echostr", echostr)
	req.URL.RawQuery = q.Encode()

	w := httptest.NewRecorder()
	ch.handleCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if strings.TrimSpace(w.Body.String()) != "hello-challenge" {
		t.Fatalf("body = %q, want hello-challenge", w.Body.String())
	}
}

func TestWeComCallback_VerifyURL_BadSignature(t *testing.T) {
	ch, _ := newTestWeComChannel(t, config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		ReceiveID:      "recv-id-1",
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	})

	req := httptest.NewRequest(http.MethodGet, "/wecom-app?msg_signature=bad&timestamp=1&nonce=2&echostr=abc", nil)
	w := httptest.NewRecorder()

	ch.handleCallback(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestWeComCallback_ReceiveJSONTextMessage_OK(t *testing.T) {
	ch, b := newTestWeComChannel(t, config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		ReceiveID:      "recv-id-1",
		AllowFrom:      []string{"zhangsan"},
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	})

	timestamp := "1739000001"
	nonce := "nonce-2"
	plaintext := `{"MsgId":"10001","FromUserName":"zhangsan","MsgType":"text","Content":"你好，myclaw"}`
	encrypt := testWeComEncrypt(t, ch.cfg.EncodingAESKey, ch.receiveID, plaintext)
	signature := testWeComSignature(ch.cfg.Token, timestamp, nonce, encrypt)

	body := testWeComEncryptedJSONBody(t, encrypt)
	req := httptest.NewRequest(http.MethodPost, "/wecom-app", strings.NewReader(body))
	q := req.URL.Query()
	q.Set("msg_signature", signature)
	q.Set("timestamp", timestamp)
	q.Set("nonce", nonce)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()

	ch.handleCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var reply weComReplyEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatalf("decode callback response: %v", err)
	}
	if reply.Encrypt == "" {
		t.Fatal("reply encrypt should not be empty")
	}

	ackPlain := testWeComDecrypt(t, ch.cfg.EncodingAESKey, ch.receiveID, reply.Encrypt)
	if strings.TrimSpace(ackPlain) != `"success"` {
		t.Fatalf("ack plaintext = %q, want %q", ackPlain, `"success"`)
	}

	select {
	case msg := <-b.Inbound:
		if msg.Channel != "wecom-app" {
			t.Errorf("channel = %q, want wecom-app", msg.Channel)
		}
		if msg.SenderID != "zhangsan" {
			t.Errorf("senderID = %q, want zhangsan", msg.SenderID)
		}
		if msg.ChatID != "zhangsan" {
			t.Errorf("chatID = %q, want zhangsan", msg.ChatID)
		}
		if msg.Content != "你好，myclaw" {
			t.Errorf("content = %q, want 你好，myclaw", msg.Content)
		}
	case <-time.After(time.Second):
		t.Fatal("expected inbound message")
	}
}

func TestWeComCallback_ReceiveXMLTextMessage_OK(t *testing.T) {
	ch, b := newTestWeComChannel(t, config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		ReceiveID:      "recv-id-1",
		AllowFrom:      []string{"lisi"},
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	})

	timestamp := "1739000002"
	nonce := "nonce-3"
	plaintext := `<xml><ToUserName><![CDATA[toUser]]></ToUserName><FromUserName><![CDATA[lisi]]></FromUserName><CreateTime>1739000002</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[hello xml]]></Content><MsgId>10002</MsgId><AgentID>1000002</AgentID></xml>`
	encrypt := testWeComEncrypt(t, ch.cfg.EncodingAESKey, ch.receiveID, plaintext)
	signature := testWeComSignature(ch.cfg.Token, timestamp, nonce, encrypt)

	body := testWeComEncryptedXMLBody(encrypt, signature, timestamp, nonce)
	req := httptest.NewRequest(http.MethodPost, "/wecom-app", strings.NewReader(body))
	q := req.URL.Query()
	q.Set("msg_signature", signature)
	q.Set("timestamp", timestamp)
	q.Set("nonce", nonce)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()

	ch.handleCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	select {
	case msg := <-b.Inbound:
		if msg.SenderID != "lisi" {
			t.Errorf("senderID = %q, want lisi", msg.SenderID)
		}
		if msg.Content != "hello xml" {
			t.Errorf("content = %q, want hello xml", msg.Content)
		}
	case <-time.After(time.Second):
		t.Fatal("expected inbound message")
	}
}

func TestWeComCallback_AllowAllWhenAllowListEmpty(t *testing.T) {
	ch, b := newTestWeComChannel(t, config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		ReceiveID:      "recv-id-1",
		AllowFrom:      []string{},
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	})

	timestamp := "1739000003"
	nonce := "nonce-4"
	plaintext := `{"MsgId":"10003","FromUserName":"anyone","MsgType":"text","Content":"hello"}`
	encrypt := testWeComEncrypt(t, ch.cfg.EncodingAESKey, ch.receiveID, plaintext)
	signature := testWeComSignature(ch.cfg.Token, timestamp, nonce, encrypt)
	body := testWeComEncryptedJSONBody(t, encrypt)

	req := httptest.NewRequest(http.MethodPost, "/wecom-app", strings.NewReader(body))
	q := req.URL.Query()
	q.Set("msg_signature", signature)
	q.Set("timestamp", timestamp)
	q.Set("nonce", nonce)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()

	ch.handleCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	select {
	case msg := <-b.Inbound:
		if msg.Content != "hello" {
			t.Errorf("Content = %q, want hello", msg.Content)
		}
		if msg.SenderID != "anyone" {
			t.Errorf("SenderID = %q, want anyone", msg.SenderID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("should allow all senders when allowFrom is empty")
	}
}

func TestWeComCallback_DuplicateMsgID_Dropped(t *testing.T) {
	ch, b := newTestWeComChannel(t, config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		ReceiveID:      "recv-id-1",
		AllowFrom:      []string{"zhangsan"},
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	})

	timestamp := "1739000004"
	nonce := "nonce-5"
	plaintext := `{"MsgId":"20001","FromUserName":"zhangsan","MsgType":"text","Content":"dup"}`
	encrypt := testWeComEncrypt(t, ch.cfg.EncodingAESKey, ch.receiveID, plaintext)
	signature := testWeComSignature(ch.cfg.Token, timestamp, nonce, encrypt)
	body := testWeComEncryptedJSONBody(t, encrypt)

	post := func() {
		req := httptest.NewRequest(http.MethodPost, "/wecom-app", strings.NewReader(body))
		q := req.URL.Query()
		q.Set("msg_signature", signature)
		q.Set("timestamp", timestamp)
		q.Set("nonce", nonce)
		req.URL.RawQuery = q.Encode()
		w := httptest.NewRecorder()
		ch.handleCallback(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
	}

	post()
	post()
	time.Sleep(50 * time.Millisecond)

	count := 0
	for {
		select {
		case <-b.Inbound:
			count++
		default:
			if count != 1 {
				t.Fatalf("inbound count = %d, want 1", count)
			}
			return
		}
	}
}

func TestWeComChannel_Send_Success(t *testing.T) {
	b := bus.NewMessageBus(10)
	mock := &mockWeComClient{}

	ch, err := NewWeComChannelWithFactory(config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		AllowFrom:      []string{"zhangsan"},
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	}, b, mockWeComClientFactory(mock))
	if err != nil {
		t.Fatalf("new channel error: %v", err)
	}
	ch.client = mock

	err = ch.Send(bus.OutboundMessage{ChatID: "zhangsan", Content: "pong"})
	if err != nil {
		t.Fatalf("send error: %v", err)
	}

	if len(mock.sent) != 1 {
		t.Fatalf("sent count = %d, want 1", len(mock.sent))
	}
	if mock.sent[0].ChatID != "zhangsan" {
		t.Errorf("chatID = %q, want zhangsan", mock.sent[0].ChatID)
	}
	if mock.sent[0].Content != "pong" {
		t.Errorf("content = %q, want pong", mock.sent[0].Content)
	}
}

func TestWeComChannel_Send_MissingChatID(t *testing.T) {
	b := bus.NewMessageBus(10)
	mock := &mockWeComClient{}

	ch, err := NewWeComChannelWithFactory(config.WeComAppConfig{
		Token:          "verify-token",
		EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
		AllowFrom:      []string{"zhangsan"},
		CorpID:         "wwcorp",
		CorpSecret:     "corp-secret",
		AgentID:        1000002,
	}, b, mockWeComClientFactory(mock))
	if err != nil {
		t.Fatalf("new channel error: %v", err)
	}
	ch.client = mock

	err = ch.Send(bus.OutboundMessage{ChatID: "", Content: "pong"})
	if err == nil {
		t.Fatal("expected missing chat id error")
	}
}

func TestChannelManager_WeComAppEnabled_MissingConfig(t *testing.T) {
	b := bus.NewMessageBus(10)
	_, err := NewChannelManager(config.ChannelsConfig{
		WeComApp: config.WeComAppConfig{Enabled: true},
	}, b)
	if err == nil {
		t.Fatal("expected error for missing wecom-app required config")
	}
}

func TestChannelManager_WeComAppEnabled(t *testing.T) {
	b := bus.NewMessageBus(10)
	m, err := NewChannelManager(config.ChannelsConfig{
		WeComApp: config.WeComAppConfig{
			Enabled:        true,
			Token:          "verify-token",
			EncodingAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
			AllowFrom:      []string{"zhangsan"},
			CorpID:         "wwcorp",
			CorpSecret:     "corp-secret",
			AgentID:        1000002,
		},
	}, b)
	if err != nil {
		t.Fatalf("new channel manager error: %v", err)
	}

	found := false
	for _, name := range m.EnabledChannels() {
		if name == "wecom-app" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("enabled channels does not include wecom-app: %v", m.EnabledChannels())
	}
}

func TestWeComClient_Send_IntegrationShape(t *testing.T) {
	getTokenCalls := 0
	sendCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			getTokenCalls++
			if got := r.URL.Query().Get("corpid"); got != "corp-id" {
				t.Fatalf("corpid = %q, want corp-id", got)
			}
			if got := r.URL.Query().Get("corpsecret"); got != "corp-secret" {
				t.Fatalf("corpsecret = %q, want corp-secret", got)
			}
			io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"token-a","expires_in":7200}`)
		case "/cgi-bin/message/send":
			sendCalls++
			if got := r.URL.Query().Get("access_token"); got != "token-a" {
				t.Fatalf("access_token = %q, want token-a", got)
			}
			body, _ := io.ReadAll(r.Body)
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("invalid send payload json: %v", err)
			}
			if payload["msgtype"] != "text" {
				t.Errorf("msgtype = %v, want text", payload["msgtype"])
			}
			if payload["touser"] != "zhangsan" {
				t.Errorf("touser = %v, want zhangsan", payload["touser"])
			}
			if int(payload["agentid"].(float64)) != 1000002 {
				t.Errorf("agentid = %v, want 1000002", payload["agentid"])
			}
			text := payload["text"].(map[string]any)
			if text["content"] != "hello from test" {
				t.Errorf("content = %v, want hello from test", text["content"])
			}
			io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &defaultWeComClient{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cfg: config.WeComAppConfig{
			CorpID:     "corp-id",
			CorpSecret: "corp-secret",
			AgentID:    1000002,
			APIBaseURL: ts.URL,
		},
	}

	err := client.SendMessage(context.Background(), bus.OutboundMessage{ChatID: "zhangsan", Content: "hello from test"})
	if err != nil {
		t.Fatalf("send message: %v", err)
	}

	if getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1", getTokenCalls)
	}
	if sendCalls != 1 {
		t.Fatalf("send calls = %d, want 1", sendCalls)
	}
}

func TestWeComClient_Send_Markdown_IntegrationShape(t *testing.T) {
	getTokenCalls := 0
	sendCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			getTokenCalls++
			io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"token-md","expires_in":7200}`)
		case "/cgi-bin/message/send":
			sendCalls++
			if got := r.URL.Query().Get("access_token"); got != "token-md" {
				t.Fatalf("access_token = %q, want token-md", got)
			}
			body, _ := io.ReadAll(r.Body)
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("invalid send payload json: %v", err)
			}
			if payload["msgtype"] != "markdown" {
				t.Errorf("msgtype = %v, want markdown", payload["msgtype"])
			}
			if payload["touser"] != "zhangsan" {
				t.Errorf("touser = %v, want zhangsan", payload["touser"])
			}
			markdown := payload["markdown"].(map[string]any)
			if markdown["content"] != "**hello markdown**" {
				t.Errorf("markdown content = %v, want **hello markdown**", markdown["content"])
			}
			if _, ok := payload["text"]; ok {
				t.Error("unexpected text field for markdown message")
			}
			io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &defaultWeComClient{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cfg: config.WeComAppConfig{
			CorpID:     "corp-id",
			CorpSecret: "corp-secret",
			AgentID:    1000002,
			APIBaseURL: ts.URL,
		},
	}

	err := client.SendMessage(context.Background(), bus.OutboundMessage{
		ChatID:  "zhangsan",
		Content: "**hello markdown**",
		Metadata: map[string]any{
			"msgtype": "markdown",
		},
	})
	if err != nil {
		t.Fatalf("send message: %v", err)
	}

	if getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1", getTokenCalls)
	}
	if sendCalls != 1 {
		t.Fatalf("send calls = %d, want 1", sendCalls)
	}
}

func TestWeComClient_Send_MarkdownTruncateLongContent(t *testing.T) {
	getTokenCalls := 0
	sendCalls := 0
	var receivedContent string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			getTokenCalls++
			io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"token-md-trunc","expires_in":7200}`)
		case "/cgi-bin/message/send":
			sendCalls++
			body, _ := io.ReadAll(r.Body)
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("invalid send payload json: %v", err)
			}
			markdown := payload["markdown"].(map[string]any)
			receivedContent = markdown["content"].(string)
			io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &defaultWeComClient{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cfg: config.WeComAppConfig{
			CorpID:     "corp-id",
			CorpSecret: "corp-secret",
			AgentID:    1000002,
			APIBaseURL: ts.URL,
		},
	}

	content := strings.Repeat("B", 5000)
	err := client.SendMessage(context.Background(), bus.OutboundMessage{
		ChatID:  "zhangsan",
		Content: content,
		Metadata: map[string]any{
			"msgtype": "markdown",
		},
	})
	if err != nil {
		t.Fatalf("send message: %v", err)
	}

	if getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1", getTokenCalls)
	}
	if sendCalls != 1 {
		t.Fatalf("send calls = %d, want 1", sendCalls)
	}
	if len([]byte(receivedContent)) > 2048 {
		t.Fatalf("markdown content bytes = %d, want <= 2048", len([]byte(receivedContent)))
	}
}

func TestWeComClient_Send_TruncateLongContent(t *testing.T) {
	getTokenCalls := 0
	sendCalls := 0
	var receivedContent string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			getTokenCalls++
			io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"token-b","expires_in":7200}`)
		case "/cgi-bin/message/send":
			sendCalls++
			body, _ := io.ReadAll(r.Body)
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("invalid send payload json: %v", err)
			}
			text := payload["text"].(map[string]any)
			receivedContent = text["content"].(string)
			io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &defaultWeComClient{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cfg: config.WeComAppConfig{
			CorpID:     "corp-id",
			CorpSecret: "corp-secret",
			AgentID:    1000002,
			APIBaseURL: ts.URL,
		},
	}

	content := strings.Repeat("A", 5000)
	err := client.SendMessage(context.Background(), bus.OutboundMessage{ChatID: "zhangsan", Content: content})
	if err != nil {
		t.Fatalf("send message: %v", err)
	}

	if getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1", getTokenCalls)
	}
	if sendCalls != 1 {
		t.Fatalf("send calls = %d, want 1", sendCalls)
	}
	if len([]byte(receivedContent)) > 2048 {
		t.Fatalf("content bytes = %d, want <= 2048", len([]byte(receivedContent)))
	}
}

func TestWeComClient_Send_RetryTransientErrcode(t *testing.T) {
	getTokenCalls := 0
	sendCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			getTokenCalls++
			io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"token-c","expires_in":7200}`)
		case "/cgi-bin/message/send":
			sendCalls++
			if sendCalls == 1 {
				io.WriteString(w, `{"errcode":-1,"errmsg":"system busy"}`)
				return
			}
			io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &defaultWeComClient{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cfg: config.WeComAppConfig{
			CorpID:     "corp-id",
			CorpSecret: "corp-secret",
			AgentID:    1000002,
			APIBaseURL: ts.URL,
		},
	}

	err := client.SendMessage(context.Background(), bus.OutboundMessage{ChatID: "zhangsan", Content: "retry me"})
	if err != nil {
		t.Fatalf("send message: %v", err)
	}
	if getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1", getTokenCalls)
	}
	if sendCalls != 2 {
		t.Fatalf("send calls = %d, want 2", sendCalls)
	}
}

func TestWeComClient_Send_NoRetryOnPayloadErrcode(t *testing.T) {
	getTokenCalls := 0
	sendCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			getTokenCalls++
			io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"token-d","expires_in":7200}`)
		case "/cgi-bin/message/send":
			sendCalls++
			io.WriteString(w, `{"errcode":44004,"errmsg":"content size out of limit"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &defaultWeComClient{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cfg: config.WeComAppConfig{
			CorpID:     "corp-id",
			CorpSecret: "corp-secret",
			AgentID:    1000002,
			APIBaseURL: ts.URL,
		},
	}

	err := client.SendMessage(context.Background(), bus.OutboundMessage{ChatID: "zhangsan", Content: "payload error"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "44004") {
		t.Fatalf("error = %v, want errcode 44004", err)
	}
	if getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1", getTokenCalls)
	}
	if sendCalls != 1 {
		t.Fatalf("send calls = %d, want 1", sendCalls)
	}
}

func TestWeComClient_Send_UseAccessTokenCache(t *testing.T) {
	getTokenCalls := 0
	sendCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			getTokenCalls++
			io.WriteString(w, `{"errcode":0,"errmsg":"ok","access_token":"token-cache","expires_in":7200}`)
		case "/cgi-bin/message/send":
			sendCalls++
			io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &defaultWeComClient{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cfg: config.WeComAppConfig{
			CorpID:     "corp-id",
			CorpSecret: "corp-secret",
			AgentID:    1000002,
			APIBaseURL: ts.URL,
		},
	}

	if err := client.SendMessage(context.Background(), bus.OutboundMessage{ChatID: "zhangsan", Content: "first"}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if err := client.SendMessage(context.Background(), bus.OutboundMessage{ChatID: "lisi", Content: "second"}); err != nil {
		t.Fatalf("second send: %v", err)
	}

	if getTokenCalls != 1 {
		t.Fatalf("gettoken calls = %d, want 1", getTokenCalls)
	}
	if sendCalls != 2 {
		t.Fatalf("send calls = %d, want 2", sendCalls)
	}
}

func newTestWeComChannel(t *testing.T, cfg config.WeComAppConfig) (*WeComChannel, *bus.MessageBus) {
	t.Helper()
	b := bus.NewMessageBus(10)
	mock := &mockWeComClient{}
	ch, err := NewWeComChannelWithFactory(cfg, b, mockWeComClientFactory(mock))
	if err != nil {
		t.Fatalf("new wecom-app channel error: %v", err)
	}
	ch.client = mock
	return ch, b
}

func testWeComEncryptedJSONBody(t *testing.T, encrypt string) string {
	t.Helper()
	body := map[string]string{"encrypt": encrypt}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal encrypted body: %v", err)
	}
	return string(data)
}

func testWeComEncryptedXMLBody(encrypt, signature, timestamp, nonce string) string {
	return fmt.Sprintf(`<xml><Encrypt><![CDATA[%s]]></Encrypt><MsgSignature><![CDATA[%s]]></MsgSignature><TimeStamp>%s</TimeStamp><Nonce><![CDATA[%s]]></Nonce></xml>`, encrypt, signature, timestamp, nonce)
}

func testWeComEncrypt(t *testing.T, encodingAESKey, receiveID, plaintext string) string {
	t.Helper()
	aesKey, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		t.Fatalf("decode aes key: %v", err)
	}
	if len(aesKey) != 32 {
		t.Fatalf("invalid aes key len: %d", len(aesKey))
	}

	random16 := []byte("0123456789abcdef")
	msg := []byte(plaintext)
	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(msg)))
	raw := append(append(append(random16, msgLen...), msg...), []byte(receiveID)...)

	padded := testPKCS7Pad(raw, 32)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	iv := aesKey[:16]
	mode := cipher.NewCBCEncrypter(block, iv)
	cipherData := make([]byte, len(padded))
	mode.CryptBlocks(cipherData, padded)

	return base64.StdEncoding.EncodeToString(cipherData)
}

func testWeComDecrypt(t *testing.T, encodingAESKey, expectedReceiveID, encrypted string) string {
	t.Helper()
	aesKey, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		t.Fatalf("decode aes key: %v", err)
	}
	if len(aesKey) != 32 {
		t.Fatalf("invalid aes key len: %d", len(aesKey))
	}

	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("decode encrypted body: %v", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	iv := aesKey[:16]
	mode := cipher.NewCBCDecrypter(block, iv)
	plain := make([]byte, len(raw))
	mode.CryptBlocks(plain, raw)

	plain, err = pkcs7Unpad(plain, 32)
	if err != nil {
		t.Fatalf("pkcs7 unpad: %v", err)
	}

	if len(plain) < 20 {
		t.Fatalf("plaintext too short: %d", len(plain))
	}
	msgLen := int(binary.BigEndian.Uint32(plain[16:20]))
	if msgLen < 0 || 20+msgLen > len(plain) {
		t.Fatalf("invalid msg length: %d", msgLen)
	}

	msg := string(plain[20 : 20+msgLen])
	receiveID := string(plain[20+msgLen:])
	if expectedReceiveID != "" && receiveID != expectedReceiveID {
		t.Fatalf("receiveID mismatch: got %q want %q", receiveID, expectedReceiveID)
	}

	return msg
}

func testPKCS7Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	if padding == 0 {
		padding = blockSize
	}
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func testWeComSignature(token, timestamp, nonce, data string) string {
	items := []string{token, timestamp, nonce, data}
	sort.Strings(items)
	s := strings.Join(items, "")
	sum := sha1.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}
