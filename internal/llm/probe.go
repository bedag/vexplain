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

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"
)

// Probe checks that the endpoint answers, accepts the key and serves the model, and returns how long
// it took. hc is the HTTP client for the requests; nil means the default client that New uses.
//
// It sends GET {BaseURL}/models. An endpoint without a models endpoint (404 or 405) is asked for a
// chat completion of one token instead, with the message "ping". The result:
//
//   - nil: the model is listed, or the chat request worked, or the endpoint answered 429, which
//     means that it is up and busy
//   - ErrUnauthorized: a 401 or 403
//   - ErrModelNotFound: a list without the model, or, from the chat request, a 400 or 404, because
//     some gateways answer an unknown model with a 400
//   - ErrUnreachable: a network error, a deadline, a 5xx, and every answer outside the OpenAI API:
//     any other status, a redirect included, which the probe never follows, and an answer that is
//     no model list or no chat completion. The error carries the status code, so an admin sees why.
//
// A probe that the caller cancels returns an error that wraps context.Canceled and no sentinel,
// because that says nothing about the endpoint. Config.Timeout, with the defaults of New, applies
// to each request that the probe makes. A probe is a check and not model work, so it records no
// observation, and it doesn't wait for the request slots of a Client.
func Probe(ctx context.Context, cfg Config, hc *http.Client) (time.Duration, error) {
	c := New(cfg, WithHTTPClient(hc))
	start := time.Now()
	if err := c.probe(ctx); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// probe asks the models endpoint, and the chat endpoint if there is no models endpoint.
func (c *Client) probe(ctx context.Context) error {
	status, answer, err := c.send(ctx, http.MethodGet, "/models", nil)
	if err == nil {
		return c.checkModels(status, answer)
	}
	var refused *StatusError
	if !errors.As(err, &refused) {
		return err // No answer came, and send says why.
	}
	switch refused.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return c.probeChat(ctx)
	case http.StatusTooManyRequests:
		return nil
	}
	return unusable(refused)
}

// modelEntry is one entry of the list of a models endpoint.
type modelEntry struct {
	ID string `json:"id"`
}

// checkModels checks the answer of a models endpoint for the model.
func (c *Client) checkModels(status int, answer []byte) error {
	var list struct {
		Data []modelEntry `json:"data"`
	}
	if status != http.StatusOK || json.Unmarshal(answer, &list) != nil {
		return &StatusError{Code: status, reason: "the answer is not a model list", class: ErrUnreachable}
	}
	if !slices.ContainsFunc(list.Data, func(m modelEntry) bool { return m.ID == c.model }) {
		return &StatusError{Code: status, reason: "the endpoint does not list the model", class: ErrModelNotFound}
	}
	return nil
}

// probeChat asks for a completion of one token, for an endpoint that has no models endpoint.
func (c *Client) probeChat(ctx context.Context) error {
	_, err := c.complete(ctx, Request{
		Messages:  []Message{{Role: "user", Content: "ping"}},
		MaxTokens: 1,
	})
	var refused *StatusError
	if err == nil || !errors.As(err, &refused) {
		return err
	}
	switch refused.Code {
	case http.StatusBadRequest, http.StatusNotFound:
		return &StatusError{Code: refused.Code, reason: "the endpoint does not serve the model", class: ErrModelNotFound}
	case http.StatusTooManyRequests:
		return nil
	}
	return unusable(refused)
}

// unusable gives an error that no sentinel covers the class ErrUnreachable. An endpoint that answers
// outside the OpenAI API isn't usable, and the status code in the error says why.
func unusable(refused *StatusError) error {
	if refused.class != nil {
		return refused
	}
	return &StatusError{Code: refused.Code, reason: refused.reason, class: ErrUnreachable}
}
