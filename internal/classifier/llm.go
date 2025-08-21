package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ghostsecurity/wraith/internal/config"
)

// LLMClient interface allows for different LLM providers
type LLMClient interface {
	Chat(ctx context.Context, messages []Message) (*ChatResponse, error)
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Content string `json:"content"`
}

// OpenAIClient implements LLMClient for OpenAI API
type OpenAIClient struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

// AnthropicClient implements LLMClient for Anthropic API
type AnthropicClient struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

// VertexClient implements LLMClient for Google Vertex AI
type VertexClient struct {
	projectID string
	location  string
	model     string
	client    *http.Client
}

func NewLLMClient(cfg *config.LLMConfig) (LLMClient, error) {
	switch cfg.Provider {
	case "openai":
		return NewOpenAIClient(cfg)
	case "anthropic":
		return NewAnthropicClient(cfg)
	case "vertex":
		return NewVertexClient(cfg)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", cfg.Provider)
	}
}

func NewOpenAIClient(cfg *config.LLMConfig) (*OpenAIClient, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
	}

	return &OpenAIClient{
		apiKey:   cfg.APIKey,
		model:    cfg.Model,
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

func NewAnthropicClient(cfg *config.LLMConfig) (*AnthropicClient, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.anthropic.com/v1"
	}

	return &AnthropicClient{
		apiKey:   cfg.APIKey,
		model:    cfg.Model,
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

func NewVertexClient(cfg *config.LLMConfig) (*VertexClient, error) {
	projectID, ok := cfg.Options["project_id"].(string)
	if !ok {
		return nil, fmt.Errorf("project_id required for Vertex AI")
	}

	location, ok := cfg.Options["location"].(string)
	if !ok {
		location = "us-central1" // Default location
	}

	return &VertexClient{
		projectID: projectID,
		location:  location,
		model:     cfg.Model,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

// OpenAI API implementation
func (c *OpenAIClient) Chat(ctx context.Context, messages []Message) (*ChatResponse, error) {
	payload := map[string]interface{}{
		"model":    c.model,
		"messages": messages,
	}

	return c.makeRequest(ctx, "/chat/completions", payload)
}

func (c *OpenAIClient) makeRequest(ctx context.Context, endpoint string, payload map[string]interface{}) (*ChatResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	return &ChatResponse{
		Content: result.Choices[0].Message.Content,
	}, nil
}

// Anthropic API implementation
func (c *AnthropicClient) Chat(ctx context.Context, messages []Message) (*ChatResponse, error) {
	// Convert messages to Anthropic format
	var systemMessage string
	var userMessages []Message

	for _, msg := range messages {
		if msg.Role == "system" {
			systemMessage = msg.Content
		} else {
			userMessages = append(userMessages, msg)
		}
	}

	payload := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 4096,
		"messages":   userMessages,
	}

	if systemMessage != "" {
		payload["system"] = systemMessage
	}

	return c.makeRequest(ctx, "/messages", payload)
}

func (c *AnthropicClient) makeRequest(ctx context.Context, endpoint string, payload map[string]interface{}) (*ChatResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no content in response")
	}

	return &ChatResponse{
		Content: result.Content[0].Text,
	}, nil
}

// Vertex AI implementation (simplified - would need proper auth in production)
func (c *VertexClient) Chat(ctx context.Context, messages []Message) (*ChatResponse, error) {
	// This is a simplified implementation
	// In production, you'd use the Google Cloud SDK and proper authentication
	return nil, fmt.Errorf("Vertex AI implementation requires Google Cloud SDK setup")
}
