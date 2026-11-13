package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

// httpClient does not follow redirects: an API key is sent to the configured endpoint
// and nowhere else.
func httpClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Minute, // a backstop; every request carries its own deadline
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkEndpoint accepts an https URL, or an http one on loopback.
func checkEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("endpoint must be a plain URL such as https://host/v1")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) {
		return nil, errors.New("endpoint must use https (http is accepted on loopback only)")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// post sends a JSON body and decodes a JSON answer. Errors name the status and never
// quote the response, which could repeat the request or carry a provider's free text.
func post(ctx context.Context, c *http.Client, u string, header http.Header, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("request failed: %w", ue.Err) // without the URL
		}
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("reading the response failed")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("provider answered HTTP %d", resp.StatusCode)
	}
	if len(data) > maxResponseBytes {
		return errors.New("response too large")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("response is not JSON")
	}
	return nil
}

// OpenAI speaks the OpenAI-compatible chat completions API. It serves two roles: the
// local analyst (the gateway's own llama.cpp server on loopback) and an optional hosted
// provider.
type OpenAI struct {
	name     string
	endpoint string
	key      string
	model    string
	external bool
	extra    map[string]any
	client   *http.Client
}

// NewOpenAI returns an adapter for a hosted OpenAI-compatible endpoint (a base URL ending
// in /v1). The key comes from the environment, never from a file in the repository.
func NewOpenAI(endpoint, key, model string) (*OpenAI, error) {
	u, err := checkEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if key == "" || model == "" {
		return nil, errors.New("an API key and a model name are required")
	}
	return &OpenAI{name: "openai", endpoint: u.String(), key: key, model: model, external: !loopback(u.Hostname()), client: httpClient()}, nil
}

// NewLocal returns the adapter for the gateway's own model server. The endpoint must be
// on loopback; model is the bundle's name for the model file being served.
func NewLocal(endpoint, key, model string) (*OpenAI, error) {
	u, err := checkEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if !loopback(u.Hostname()) {
		return nil, errors.New("the local analyst only talks to loopback")
	}
	return &OpenAI{name: "local", endpoint: u.String(), key: key, model: model, client: httpClient(),
		// Models with an optional reasoning phase answer directly: a verdict is short, and
		// the time budget on a CPU is spent on the answer.
		extra: map[string]any{"chat_template_kwargs": map[string]any{"enable_thinking": false}, "cache_prompt": true}}, nil
}

func (o *OpenAI) Name() string   { return o.name }
func (o *OpenAI) Model() string  { return o.model }
func (o *OpenAI) External() bool { return o.external }

func (o *OpenAI) Complete(ctx context.Context, r Request) (Response, error) {
	body := map[string]any{
		"model": o.model,
		"messages": []map[string]string{
			{"role": "system", "content": r.System},
			{"role": "user", "content": r.User},
		},
		"temperature": 0,
		"max_tokens":  r.MaxTokens,
	}
	if len(r.Schema) > 0 {
		body["response_format"] = map[string]any{"type": "json_schema",
			"json_schema": map[string]any{"name": "verdict", "strict": true, "schema": r.Schema}}
	}
	for k, v := range o.extra {
		body[k] = v
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	h := http.Header{}
	if o.key != "" {
		h.Set("Authorization", "Bearer "+o.key)
	}
	if err := post(ctx, o.client, o.endpoint+"/chat/completions", h, body, &out); err != nil {
		return Response{}, err
	}
	if len(out.Choices) == 0 {
		return Response{}, errors.New("provider returned no answer")
	}
	return Response{Text: out.Choices[0].Message.Content, TokensIn: out.Usage.PromptTokens, TokensOut: out.Usage.CompletionTokens}, nil
}

// Anthropic speaks the Anthropic messages API. The verdict is requested as the input of
// a single forced tool call, which the API shapes to the schema.
type Anthropic struct {
	endpoint string
	key      string
	model    string
	client   *http.Client
}

const DefaultAnthropicEndpoint = "https://api.anthropic.com"

func NewAnthropic(endpoint, key, model string) (*Anthropic, error) {
	if endpoint == "" {
		endpoint = DefaultAnthropicEndpoint
	}
	u, err := checkEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if key == "" || model == "" {
		return nil, errors.New("an API key and a model name are required")
	}
	return &Anthropic{endpoint: u.String(), key: key, model: model, client: httpClient()}, nil
}

func (a *Anthropic) Name() string   { return "anthropic" }
func (a *Anthropic) Model() string  { return a.model }
func (a *Anthropic) External() bool { return true }

func (a *Anthropic) Complete(ctx context.Context, r Request) (Response, error) {
	const tool = "submit_verdict"
	body := map[string]any{
		"model":       a.model,
		"max_tokens":  r.MaxTokens,
		"temperature": 0,
		"system":      r.System,
		"messages":    []map[string]string{{"role": "user", "content": r.User}},
		"tools": []map[string]any{{"name": tool, "description": "Record the verdict for this case.",
			"input_schema": r.Schema}},
		"tool_choice": map[string]string{"type": "tool", "name": tool},
	}
	var out struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	h := http.Header{}
	h.Set("x-api-key", a.key)
	h.Set("anthropic-version", "2023-06-01")
	if err := post(ctx, a.client, a.endpoint+"/v1/messages", h, body, &out); err != nil {
		return Response{}, err
	}
	for _, c := range out.Content {
		if c.Type == "tool_use" && c.Name == tool {
			return Response{Text: string(c.Input), TokensIn: out.Usage.InputTokens, TokensOut: out.Usage.OutputTokens}, nil
		}
	}
	return Response{}, errors.New("provider returned no verdict")
}
