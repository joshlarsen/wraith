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

// LLMClient interface for OpenAI-compatible API calls
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

func NewLLMClient(cfg *config.LLMConfig) (LLMClient, error) {
	return NewOpenAIClient(cfg)
}

func NewOpenAIClient(cfg *config.LLMConfig) (*OpenAIClient, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	return &OpenAIClient{
		apiKey:   cfg.APIKey,
		model:    cfg.Model,
		endpoint: baseURL,
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
