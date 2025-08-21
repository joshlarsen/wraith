package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/ghostsecurity/wraith/internal/config"
	jsonschema "github.com/swaggest/jsonschema-go"
)

// LLMClient interface allows for different LLM providers
type LLMClient interface {
	Chat(ctx context.Context, messages []Message) (*ChatResponse, error)
	ChatStructured(ctx context.Context, messages []Message, responseStruct interface{}) (*StructuredResponse, error)
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Content      string `json:"content"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`
	TotalTokens  int    `json:"total_tokens,omitempty"`
}

type StructuredResponse struct {
	Result       interface{} `json:"result"`
	InputTokens  int         `json:"input_tokens,omitempty"`
	OutputTokens int         `json:"output_tokens,omitempty"`
	TotalTokens  int         `json:"total_tokens,omitempty"`
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

func (c *OpenAIClient) ChatStructured(ctx context.Context, messages []Message, responseStruct interface{}) (*StructuredResponse, error) {
	// Generate JSON schema from the struct
	reflector := jsonschema.Reflector{}
	schema, err := reflector.Reflect(responseStruct)
	if err != nil {
		return nil, fmt.Errorf("generating schema: %w", err)
	}

	setAdditionalPropertiesFalse(&schema)

	// Convert schema to map for JSON marshaling
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return nil, fmt.Errorf("marshaling schema: %w", err)
	}

	var schemaMap map[string]interface{}
	if err := json.Unmarshal(schemaBytes, &schemaMap); err != nil {
		return nil, fmt.Errorf("unmarshaling schema: %w", err)
	}

	payload := map[string]interface{}{
		"model":    c.model,
		"messages": messages,
		"response_format": map[string]interface{}{
			"type": "json_schema",
			"json_schema": map[string]interface{}{
				"name":   "response",
				"schema": schemaMap,
				"strict": true,
			},
		},
	}

	response, err := c.makeRequest(ctx, "/chat/completions", payload)
	if err != nil {
		return nil, err
	}

	// Unmarshal the response content directly into the struct type
	structType := reflect.TypeOf(responseStruct)
	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}

	result := reflect.New(structType).Interface()
	if err := json.Unmarshal([]byte(response.Content), result); err != nil {
		return nil, fmt.Errorf("unmarshaling structured response: %w", err)
	}

	return &StructuredResponse{
		Result:       result,
		InputTokens:  response.InputTokens,
		OutputTokens: response.OutputTokens,
		TotalTokens:  response.TotalTokens,
	}, nil
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
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	return &ChatResponse{
		Content:      result.Choices[0].Message.Content,
		InputTokens:  result.Usage.PromptTokens,
		OutputTokens: result.Usage.CompletionTokens,
		TotalTokens:  result.Usage.TotalTokens,
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

func (c *AnthropicClient) ChatStructured(ctx context.Context, messages []Message, responseStruct interface{}) (*StructuredResponse, error) {
	// Generate JSON schema from the struct
	reflector := jsonschema.Reflector{}
	schema, err := reflector.Reflect(responseStruct)
	if err != nil {
		return nil, fmt.Errorf("generating schema: %w", err)
	}

	// Convert schema to map for JSON marshaling
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return nil, fmt.Errorf("marshaling schema: %w", err)
	}

	var schemaMap map[string]interface{}
	if err := json.Unmarshal(schemaBytes, &schemaMap); err != nil {
		return nil, fmt.Errorf("unmarshaling schema: %w", err)
	}

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

	// Add schema instruction to the system message
	schemaInstruction := fmt.Sprintf("\n\nYou must respond with valid JSON that matches this exact schema: %s", string(schemaBytes))
	if systemMessage != "" {
		systemMessage += schemaInstruction
	} else {
		systemMessage = "Respond with valid JSON." + schemaInstruction
	}

	payload := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 4096,
		"messages":   userMessages,
		"system":     systemMessage,
	}

	response, err := c.makeRequest(ctx, "/messages", payload)
	if err != nil {
		return nil, err
	}

	// Unmarshal the response content directly into the struct type
	structType := reflect.TypeOf(responseStruct)
	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}

	result := reflect.New(structType).Interface()
	if err := json.Unmarshal([]byte(response.Content), result); err != nil {
		return nil, fmt.Errorf("unmarshaling structured response: %w", err)
	}

	return &StructuredResponse{
		Result:       result,
		InputTokens:  response.InputTokens,
		OutputTokens: response.OutputTokens,
		TotalTokens:  response.TotalTokens,
	}, nil
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
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Content) == 0 {
		return nil, fmt.Errorf("no content in response")
	}

	return &ChatResponse{
		Content:      result.Content[0].Text,
		InputTokens:  result.Usage.InputTokens,
		OutputTokens: result.Usage.OutputTokens,
		TotalTokens:  result.Usage.InputTokens + result.Usage.OutputTokens,
	}, nil
}

// Vertex AI implementation (simplified - would need proper auth in production)
func (c *VertexClient) Chat(ctx context.Context, messages []Message) (*ChatResponse, error) {
	// This is a simplified implementation
	// In production, you'd use the Google Cloud SDK and proper authentication
	return nil, fmt.Errorf("Vertex AI implementation requires Google Cloud SDK setup")
}

func (c *VertexClient) ChatStructured(ctx context.Context, messages []Message, responseStruct interface{}) (*StructuredResponse, error) {
	// This is a simplified implementation
	// In production, you'd use the Google Cloud SDK and proper authentication
	return nil, fmt.Errorf("Vertex AI structured output implementation requires Google Cloud SDK setup")
}

// setAdditionalPropertiesFalse recursively sets additionalProperties to false
// at the top level and all definitions; this is required by the OpenAI API
func setAdditionalPropertiesFalse(schema *jsonschema.Schema) {
	schema.AdditionalProperties = &jsonschema.SchemaOrBool{}
	schema.AdditionalProperties.WithTypeBoolean(false)

	if schema.Definitions != nil {
		for _, def := range schema.Definitions {
			if def.TypeObject != nil {
				setAdditionalPropertiesFalse(def.TypeObject)
			}
		}
	}
}
