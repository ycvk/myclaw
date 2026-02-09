package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const (
	DefaultModel             = "claude-sonnet-4-5-20250929"
	DefaultMaxTokens         = 8192
	DefaultTemperature       = 0.7
	DefaultMaxToolIterations = 20
	DefaultExecTimeout       = 60
	DefaultHost              = "0.0.0.0"
	DefaultPort              = 18790
	DefaultBufSize           = 100
)

type Config struct {
	Agent    AgentConfig    `json:"agent"`
	Channels ChannelsConfig `json:"channels"`
	Provider ProviderConfig `json:"provider"`
	Tools    ToolsConfig    `json:"tools"`
	Gateway  GatewayConfig  `json:"gateway"`
}

type AgentConfig struct {
	Workspace         string  `json:"workspace"`
	Model             string  `json:"model"`
	MaxTokens         int     `json:"maxTokens"`
	Temperature       float64 `json:"temperature"`
	MaxToolIterations int     `json:"maxToolIterations"`
}

type ProviderConfig struct {
	Type    string `json:"type,omitempty"` // "anthropic" (default) or "openai"
	APIKey  string `json:"apiKey"`
	BaseURL string `json:"baseUrl,omitempty"`
}

type ChannelsConfig struct {
	Telegram TelegramConfig `json:"telegram"`
	Feishu   FeishuConfig   `json:"feishu"`
	WeComApp WeComAppConfig `json:"wecom-app"`
}

type TelegramConfig struct {
	Enabled   bool     `json:"enabled"`
	Token     string   `json:"token"`
	AllowFrom []string `json:"allowFrom"`
	Proxy     string   `json:"proxy,omitempty"`
}

type FeishuConfig struct {
	Enabled           bool     `json:"enabled"`
	AppID             string   `json:"appId"`
	AppSecret         string   `json:"appSecret"`
	VerificationToken string   `json:"verificationToken"`
	EncryptKey        string   `json:"encryptKey,omitempty"`
	Port              int      `json:"port,omitempty"`
	AllowFrom         []string `json:"allowFrom"`
}

type WeComAppConfig struct {
	Enabled        bool     `json:"enabled"`
	WebhookPath    string   `json:"webhookPath,omitempty"`
	Token          string   `json:"token"`
	EncodingAESKey string   `json:"encodingAESKey"`
	ReceiveID      string   `json:"receiveId,omitempty"`
	CorpID         string   `json:"corpId,omitempty"`
	CorpSecret     string   `json:"corpSecret,omitempty"`
	AgentID        int      `json:"agentId,omitempty"`
	APIBaseURL     string   `json:"apiBaseUrl,omitempty"`
	Port           int      `json:"port,omitempty"`
	AllowFrom      []string `json:"allowFrom"`
}

type ToolsConfig struct {
	BraveAPIKey         string `json:"braveApiKey,omitempty"`
	ExecTimeout         int    `json:"execTimeout"`
	RestrictToWorkspace bool   `json:"restrictToWorkspace"`
}

type GatewayConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Agent: AgentConfig{
			Workspace:         filepath.Join(home, ".myclaw", "workspace"),
			Model:             DefaultModel,
			MaxTokens:         DefaultMaxTokens,
			Temperature:       DefaultTemperature,
			MaxToolIterations: DefaultMaxToolIterations,
		},
		Provider: ProviderConfig{},
		Channels: ChannelsConfig{},
		Tools: ToolsConfig{
			ExecTimeout:         DefaultExecTimeout,
			RestrictToWorkspace: true,
		},
		Gateway: GatewayConfig{
			Host: DefaultHost,
			Port: DefaultPort,
		},
	}
}

func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".myclaw")
}

func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.json")
}

func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read config: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	// Environment variable overrides
	if key := os.Getenv("MYCLAW_API_KEY"); key != "" {
		cfg.Provider.APIKey = key
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" && cfg.Provider.APIKey == "" {
		cfg.Provider.APIKey = key
	}
	if key := os.Getenv("ANTHROPIC_AUTH_TOKEN"); key != "" && cfg.Provider.APIKey == "" {
		cfg.Provider.APIKey = key
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" && cfg.Provider.APIKey == "" {
		cfg.Provider.APIKey = key
		if cfg.Provider.Type == "" {
			cfg.Provider.Type = "openai"
		}
	}
	if url := os.Getenv("MYCLAW_BASE_URL"); url != "" {
		cfg.Provider.BaseURL = url
	}
	if url := os.Getenv("ANTHROPIC_BASE_URL"); url != "" && cfg.Provider.BaseURL == "" {
		cfg.Provider.BaseURL = url
	}
	if token := os.Getenv("MYCLAW_TELEGRAM_TOKEN"); token != "" {
		cfg.Channels.Telegram.Token = token
	}
	if appID := os.Getenv("MYCLAW_FEISHU_APP_ID"); appID != "" {
		cfg.Channels.Feishu.AppID = appID
	}
	if appSecret := os.Getenv("MYCLAW_FEISHU_APP_SECRET"); appSecret != "" {
		cfg.Channels.Feishu.AppSecret = appSecret
	}
	if token := os.Getenv("MYCLAW_WECOM_APP_TOKEN"); token != "" {
		cfg.Channels.WeComApp.Token = token
	}
	if aesKey := os.Getenv("MYCLAW_WECOM_APP_ENCODING_AES_KEY"); aesKey != "" {
		cfg.Channels.WeComApp.EncodingAESKey = aesKey
	}
	if receiveID := os.Getenv("MYCLAW_WECOM_APP_RECEIVE_ID"); receiveID != "" {
		cfg.Channels.WeComApp.ReceiveID = receiveID
	}
	if corpID := os.Getenv("MYCLAW_WECOM_APP_CORP_ID"); corpID != "" {
		cfg.Channels.WeComApp.CorpID = corpID
	}
	if corpSecret := os.Getenv("MYCLAW_WECOM_APP_CORP_SECRET"); corpSecret != "" {
		cfg.Channels.WeComApp.CorpSecret = corpSecret
	}
	if agentID := os.Getenv("MYCLAW_WECOM_APP_AGENT_ID"); agentID != "" {
		if parsed, err := strconv.Atoi(agentID); err == nil {
			cfg.Channels.WeComApp.AgentID = parsed
		}
	}
	if apiBaseURL := os.Getenv("MYCLAW_WECOM_APP_API_BASE_URL"); apiBaseURL != "" {
		cfg.Channels.WeComApp.APIBaseURL = apiBaseURL
	}

	if cfg.Agent.Workspace == "" {
		cfg.Agent.Workspace = DefaultConfig().Agent.Workspace
	}

	return cfg, nil
}

func SaveConfig(cfg *Config) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	return os.WriteFile(ConfigPath(), data, 0644)
}
