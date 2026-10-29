/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package llm is the operator's only way to reach the language model. It holds a client for the
// chat completions API that OpenAI-compatible servers speak, a probe that checks an endpoint, and
// an observer that records the requests in the operator's metrics.
//
// The API key is a Secret, which prints as "[redacted]" in every format, in JSON and in logs. No
// error of this package carries the key, a header or any part of a response body, because some
// gateways echo the key they received in their error bodies. An error says why in a short reason
// that is fixed in this package, and carries the status code when there was an answer.
package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// redacted is what a Secret prints in place of its value.
	redacted = "[redacted]"

	// defaultTimeout bounds an exchange with the endpoint when Config.Timeout says nothing.
	defaultTimeout = 60 * time.Second
	// defaultMaxConcurrent is the number of requests in flight at once when Config.MaxConcurrent
	// says nothing.
	defaultMaxConcurrent = 1

	// maxResponseBytes caps what the client reads of a successful answer: 4 MiB. It buffers the
	// answer to decode it, and a model writes at most a few hundred KiB of JSON, tool calls
	// included, so a larger answer is an endpoint that misbehaves, and must not fill the memory of
	// the operator.
	maxResponseBytes = 4 << 20
)

// The values of Observation.Outcome.
const (
	outcomeOK           = "ok"
	outcomeError        = "error"
	outcomeUnauthorized = "unauthorized"
	outcomeTimeout      = "timeout"
)

// Secret holds the API key. Every way to print it gives "[redacted]": String, Format, MarshalJSON
// and MarshalLog. Only the HTTP layer of this package converts it with string(s).
type Secret string

// String returns "[redacted]".
func (Secret) String() string { return redacted }

// Format writes "[redacted]" whatever the verb. String alone is not enough: %#v prints Go syntax
// without calling it, and so does fmt for a verb that doesn't fit a string, such as %d. A Formatter
// takes precedence for every verb, also for a Secret in a field of a struct.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// MarshalJSON returns the JSON string "[redacted]".
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalLog returns "[redacted]". logr's loggers log the result of MarshalLog in place of a value
// that has the method.
func (Secret) MarshalLog() any { return redacted }

// Config is what a Client needs to know about an endpoint.
type Config struct {
	// BaseURL is the URL that "/chat/completions" and "/models" are appended to, for example
	// "https://llm.example/v1".
	BaseURL string
	// Model is the name of the model that the endpoint serves.
	Model string
	// APIKey is sent to the endpoint as a bearer token.
	APIKey Secret
	// Timeout bounds each exchange with the endpoint: the request and the whole answer. Zero or
	// less means 60 seconds. The wait for a free request slot does not count.
	Timeout time.Duration
	// MaxConcurrent is the number of requests that a Client has in flight at once. Zero or less
	// means 1.
	MaxConcurrent int
	// TemperatureMilli is the sampling temperature in thousandths, so 200 is 0.2. It is always
	// sent, so that 0 means 0.0 and not "the default of the server".
	TemperatureMilli int32
}

// Message is one message of a conversation.
type Message struct {
	// Role is system, user, assistant or tool.
	Role string
	// Content is the text of the message. An assistant message that only calls tools has none.
	Content string
	// ToolCalls are the tools that an assistant message calls.
	ToolCalls []ToolCall
	// ToolCallID is the ID of the tool call that a tool message answers.
	ToolCallID string
}

// Tool is a function that the model may call.
type Tool struct {
	Name        string
	Description string
	// Parameters is the JSON schema of the arguments.
	Parameters json.RawMessage
}

// ToolCall is a call of a tool that the model asked for.
type ToolCall struct {
	ID   string
	Name string
	// Arguments is the text as the server returned it. It may be invalid JSON, so the caller
	// validates it.
	Arguments string
}

// Request is one call of the model.
type Request struct {
	Messages []Message
	Tools    []Tool
	// ToolChoice is "", "auto", "required" or "none". Empty leaves it to the server.
	ToolChoice string
	// MaxTokens limits the tokens of the answer. Zero leaves it to the server.
	MaxTokens int
}

// Usage is the number of tokens that the endpoint reports for a request.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
}

// Response is the first choice of an answer.
type Response struct {
	Message      Message
	FinishReason string
	Usage        Usage
}

// Observation describes one request that a Client made to the endpoint.
type Observation struct {
	Model string
	// Outcome is ok, unauthorized (the endpoint answered 401 or 403), timeout (the request ran out
	// of time) or error (every other failure).
	Outcome string
	// Duration is the time of the exchange with the endpoint, without the wait for a request slot.
	Duration time.Duration
	// Usage is what the endpoint reported. It is zero when the request failed.
	Usage Usage
}

// The errors that tell why an endpoint can't be used. Complete wraps ErrUnauthorized and
// ErrUnreachable, and Probe wraps one of the three for every failure of the endpoint. Test for them
// with errors.Is, and for the status code with errors.As and a *StatusError.
var (
	// ErrUnauthorized means that the endpoint rejected the API key, with an HTTP 401 or 403.
	ErrUnauthorized = errors.New("the endpoint rejected the API key")
	// ErrModelNotFound means that the endpoint does not serve the model. Only Probe knows that: a
	// status of a chat request does not tell it.
	ErrModelNotFound = errors.New("the endpoint does not serve the model")
	// ErrUnreachable means that no useful answer came: a network error, a deadline, a server error,
	// or, for a probe, an answer outside the OpenAI API.
	ErrUnreachable = errors.New("the endpoint is unreachable")
)

// StatusError is the error of an answer that the client does not accept. It carries the status code
// and a short reason that is fixed in this package, and nothing of the answer.
type StatusError struct {
	// Code is the HTTP status code of the answer.
	Code   int
	reason string
	// class is the sentinel that the error wraps, if any.
	class error
}

// Error returns the reason and the status code.
func (e *StatusError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.reason, e.Code) }

// Unwrap returns the sentinel of the error, if it has one.
func (e *StatusError) Unwrap() error { return e.class }

// Option changes how New builds a Client.
type Option func(*Client)

// WithObserver sets the function that Complete calls once for every request that it made, with the
// outcome. It is called from the goroutine of the call, so it must be safe for concurrent use.
func WithObserver(observe func(Observation)) Option {
	return func(c *Client) { c.observe = observe }
}

// WithHTTPClient sets the HTTP client for the requests, for a test server or a special transport.
// The client never changes it, and it never follows a redirect, whatever the CheckRedirect of hc
// says: it uses a copy of hc for that. Without one, or with nil, the client uses a clone of
// http.DefaultTransport, which honours HTTPS_PROXY and NO_PROXY.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// errProxyRefused is the error that the default transport returns when a proxy answers a CONNECT
// request with a status other than 200. Go returns the status text of the answer as a plain error,
// which nothing tells from any other error, unlike a failure to reach the proxy at all.
var errProxyRefused = errors.New("the proxy refused the CONNECT request")

// defaultHTTPClient is the HTTP client that New and Probe use when they get none: a clone of
// http.DefaultTransport, with the proxy settings of the environment. They share it, and its
// connections, because a client of this package never changes it.
var defaultHTTPClient = sync.OnceValue(func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	// The hook runs before the transport checks the status, and the error that it returns is the
	// error of the request.
	transport.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
		if res.StatusCode != http.StatusOK {
			return errProxyRefused
		}
		return nil
	}
	return &http.Client{Transport: transport}
})

// Client talks to one OpenAI-compatible endpoint. It is safe for concurrent use: at most
// Config.MaxConcurrent calls of Complete have a request in flight, and the others wait.
//
// A Client never follows a redirect. Go keeps the Authorization header when it redirects a request
// from https to http on the same host, which would put the key on a plain connection, and an API like
// this has no reason to redirect. A redirect is an answer that Complete returns as a *StatusError
// with its status code, and that Probe takes for an answer outside the OpenAI API.
//
// No field of a Client holds the key: it lives in a closure, which a dump by reflection or by fmt
// can't read. Format prints the model and nothing else, so that no verb of fmt shows the URL
// either, which can carry credentials.
type Client struct {
	baseURL string
	model   string
	// authorize adds the credentials to a request. It is a function because it holds the key: a
	// reflection can read a field, but not the variables that a closure has captured.
	authorize   func(*http.Request)
	timeout     time.Duration
	temperature float64
	// slots is the semaphore: a call holds one of its places while it makes a request.
	slots      chan struct{}
	httpClient *http.Client
	observe    func(Observation)
}

// Format prints the client as llm.Client{model: m}, whatever the verb. It has a value receiver, so
// that a Client that is copied prints the same.
func (c Client) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "llm.Client{model: %s}", c.model)
}

// New returns a client for the endpoint that cfg describes.
func New(cfg Config, opts ...Option) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	c := &Client{
		baseURL:     strings.TrimRight(cfg.BaseURL, "/"),
		model:       cfg.Model,
		authorize:   bearer(cfg.APIKey),
		timeout:     timeout,
		temperature: float64(cfg.TemperatureMilli) / 1000,
		slots:       make(chan struct{}, maxConcurrent),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.httpClient == nil {
		c.httpClient = defaultHTTPClient()
	}
	// The copy shares the transport, and refuses redirects: the last response comes back as it is,
	// with its body unread, and the HTTP client of the caller stays as it was.
	noRedirects := *c.httpClient
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.httpClient = &noRedirects
	return c
}

// bearer returns the function that adds the key to a request as a bearer token. This is the only
// place that converts a Secret to a string.
func bearer(key Secret) func(*http.Request) {
	header := "Bearer " + string(key)
	return func(r *http.Request) { r.Header.Set("Authorization", header) }
}

// Complete posts the request to {BaseURL}/chat/completions and returns the first choice of the
// answer.
//
// At most Config.MaxConcurrent calls have a request in flight; the others wait for a slot, as long
// as ctx allows and no longer. A call that never gets a slot makes no request, returns an error
// that wraps the error of ctx, and is not observed. Config.Timeout bounds the exchange only, and
// the observed duration is that of the exchange.
//
// An error wraps ErrUnauthorized for an HTTP 401 or 403, and ErrUnreachable for a network error, a
// server error or a deadline. A deadline, the Timeout's or the caller's, also wraps
// context.DeadlineExceeded. A caller that cancels gets context.Canceled and not ErrUnreachable,
// because that says nothing about the endpoint. Any other status gives a *StatusError without a
// sentinel, a redirect included, and so does an answer that is no chat completion.
func (c *Client) Complete(ctx context.Context, req Request) (*Response, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer func() { <-c.slots }()

	start := time.Now()
	resp, err := c.complete(ctx, req)
	if c.observe != nil {
		obs := Observation{Model: c.model, Outcome: outcomeOf(err), Duration: time.Since(start)}
		if resp != nil {
			obs.Usage = resp.Usage
		}
		c.observe(obs)
	}
	return resp, err
}

// acquire waits for one of the request slots, until ctx is done.
func (c *Client) acquire(ctx context.Context) error {
	// A select picks at random when a slot is free and ctx is done, so a done context is checked
	// first: it must not make a request.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("no request was made: %w", err)
	}
	select {
	case c.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("no request slot became free: %w", ctx.Err())
	}
}

// outcomeOf returns the outcome of an observation for the error of a call.
func outcomeOf(err error) string {
	switch {
	case err == nil:
		return outcomeOK
	case errors.Is(err, context.DeadlineExceeded):
		return outcomeTimeout
	case errors.Is(err, ErrUnauthorized):
		return outcomeUnauthorized
	default:
		return outcomeError
	}
}

// complete is the request to the endpoint, without the wait for a slot and without an observation.
// Probe uses it too.
func (c *Client) complete(ctx context.Context, req Request) (*Response, error) {
	payload, err := json.Marshal(c.wireRequest(req))
	if err != nil {
		return nil, fmt.Errorf("encode the request: %w", err)
	}
	status, answer, err := c.send(ctx, http.MethodPost, "/chat/completions", payload)
	if err != nil {
		return nil, err
	}
	return decode(status, answer)
}

// send makes one exchange with the endpoint and returns the status code and the body of a 2xx
// answer. The Timeout bounds the whole exchange, up to the end of the body, and it is applied to the
// context of the request, so that the HTTP client of the caller stays as it is.
//
// The body of any other answer is never read. A status that is not 2xx gives a *StatusError, and
// a request that got no answer gives the error that noAnswer describes.
func (c *Client) send(ctx context.Context, method, path string, payload []byte) (int, []byte, error) {
	exchange, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	httpReq, err := http.NewRequestWithContext(exchange, method, c.baseURL+path, body)
	if err != nil {
		// The error quotes the URL, which can carry credentials.
		return 0, nil, fmt.Errorf("%w: the URL of the endpoint is not valid", ErrUnreachable)
	}
	c.authorize(httpReq)
	httpReq.Header.Set("Accept", "application/json")
	if payload != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return 0, nil, noAnswer(ctx, exchange, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, nil, refusal(resp.StatusCode)
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp.StatusCode, nil, noAnswer(ctx, exchange, err)
	}
	if len(answer) > maxResponseBytes {
		return resp.StatusCode, nil, &StatusError{Code: resp.StatusCode, reason: "the answer is too large"}
	}
	return resp.StatusCode, answer, nil
}

// refusal is the error for a status that is not 2xx.
func refusal(code int) *StatusError {
	switch {
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return &StatusError{Code: code, reason: "the endpoint rejected the API key", class: ErrUnauthorized}
	case code >= http.StatusInternalServerError:
		return &StatusError{Code: code, reason: "the endpoint answered with a server error", class: ErrUnreachable}
	case isRedirect(code):
		return &StatusError{Code: code, reason: "the endpoint answered with a redirect, which is not followed"}
	default:
		return &StatusError{Code: code, reason: "the endpoint refused the request"}
	}
}

// isRedirect reports whether a status is one that an HTTP client follows.
func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// noAnswer is the error for an exchange that failed before a whole answer came. ctx is the context
// of the caller and exchange the one that carries the Timeout.
//
// It never quotes err: the text of a transport error holds the URL, which can carry credentials,
// and for some errors what a proxy or server said. It names the reason in a few fixed words.
func noAnswer(ctx, exchange context.Context, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		// The caller gave up. That says nothing about the endpoint.
		return fmt.Errorf("the request was cancelled: %w", context.Canceled)
	case errors.Is(exchange.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: the request timed out: %w", ErrUnreachable, context.DeadlineExceeded)
	default:
		return fmt.Errorf("%w: %s", ErrUnreachable, reason(err))
	}
}

// reason says in a few fixed words why a request got no answer. The most common causes get their
// own words, because they are what an admin has to fix; anything else is "the request failed".
//
// A failure of the proxy comes first. net/http wraps the failure to reach a proxy, whether it does not
// resolve, refuses or times out, as a *net.OpError with the operation "proxyconnect", with the error
// of the dial inside. That inner error names the host of the proxy, so a check for it before this one
// would blame the endpoint. A proxy that answers a CONNECT request with an error is the other case,
// and only the default client reports it as such: see errProxyRefused.
func reason(err error) string {
	var (
		proxy    *net.OpError
		timeout  net.Error
		resolve  *net.DNSError
		verified *tls.CertificateVerificationError
	)
	switch {
	case errors.Is(err, errProxyRefused), errors.As(err, &proxy) && proxy.Op == "proxyconnect":
		return "the connection through the proxy failed"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "the connection timed out"
	case errors.As(err, &resolve):
		return "the host name does not resolve"
	case errors.As(err, &verified):
		return "the TLS certificate was not accepted"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the connection was refused"
	default:
		return "the request failed"
	}
}

// The JSON of the chat completions API. Content is a pointer, so that it can be null.
type (
	wireRequest struct {
		Model       string        `json:"model"`
		Messages    []wireMessage `json:"messages"`
		Tools       []wireTool    `json:"tools,omitempty"`
		ToolChoice  string        `json:"tool_choice,omitempty"`
		Temperature float64       `json:"temperature"`
		MaxTokens   int           `json:"max_tokens,omitempty"`
	}
	wireMessage struct {
		Role       string         `json:"role"`
		Content    *string        `json:"content"`
		ToolCalls  []wireToolCall `json:"tool_calls,omitempty"`
		ToolCallID string         `json:"tool_call_id,omitempty"`
	}
	wireToolCall struct {
		ID       string           `json:"id"`
		Type     string           `json:"type"`
		Function wireFunctionCall `json:"function"`
	}
	// wireFunctionCall always has arguments, even empty ones: the API requires the field.
	wireFunctionCall struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	wireTool struct {
		Type     string          `json:"type"`
		Function wireFunctionDef `json:"function"`
	}
	wireFunctionDef struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters,omitempty"`
	}
	wireResponse struct {
		Choices []struct {
			Message      wireMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
)

// functionType is the type of every tool and tool call: the API knows no other.
const functionType = "function"

// wireRequest returns the request as the API takes it. The temperature is always set, so 0 stays 0.
func (c *Client) wireRequest(req Request) wireRequest {
	messages := make([]wireMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		messages = append(messages, wireMessageOf(m))
	}
	tools := make([]wireTool, 0, len(req.Tools))
	for _, t := range req.Tools {
		tools = append(tools, wireTool{Type: functionType, Function: wireFunctionDef(t)})
	}
	return wireRequest{
		Model:       c.model,
		Messages:    messages,
		Tools:       tools,
		ToolChoice:  req.ToolChoice,
		Temperature: c.temperature,
		MaxTokens:   req.MaxTokens,
	}
}

// wireMessageOf returns a message as the API takes it. Every message has a content, which may be
// empty, but an assistant message that only calls tools: servers send null for it, so null goes
// back. The arguments of a tool call go as they are, valid JSON or not.
func wireMessageOf(m Message) wireMessage {
	wire := wireMessage{Role: m.Role, ToolCallID: m.ToolCallID}
	if m.Content != "" || len(m.ToolCalls) == 0 {
		wire.Content = &m.Content
	}
	for _, call := range m.ToolCalls {
		wire.ToolCalls = append(wire.ToolCalls, wireToolCall{
			ID:       call.ID,
			Type:     functionType,
			Function: wireFunctionCall{Name: call.Name, Arguments: call.Arguments},
		})
	}
	return wire
}

// decode returns the first choice of the body of a 2xx answer. The error of the decoder is not
// passed on, because it can quote the body.
func decode(status int, answer []byte) (*Response, error) {
	var wire wireResponse
	if err := json.Unmarshal(answer, &wire); err != nil {
		return nil, &StatusError{Code: status, reason: "the answer is not a chat completion"}
	}
	if len(wire.Choices) == 0 {
		return nil, &StatusError{Code: status, reason: "the answer has no choices"}
	}
	choice := wire.Choices[0]
	resp := &Response{
		Message:      Message{Role: choice.Message.Role},
		FinishReason: choice.FinishReason,
		Usage:        Usage{PromptTokens: wire.Usage.PromptTokens, CompletionTokens: wire.Usage.CompletionTokens},
	}
	if choice.Message.Content != nil {
		resp.Message.Content = *choice.Message.Content
	}
	for _, call := range choice.Message.ToolCalls {
		resp.Message.ToolCalls = append(resp.Message.ToolCalls, ToolCall{
			ID:        call.ID,
			Name:      call.Function.Name,
			Arguments: call.Function.Arguments,
		})
	}
	return resp, nil
}
