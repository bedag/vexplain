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

package llm_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

func TestSecretRedacts(t *testing.T) {
	key := llm.Secret(testKey)
	cfg := llm.Config{BaseURL: exampleURL, Model: testModel, APIKey: key, Timeout: time.Minute}
	client := llm.New(cfg)
	// fmt can't call a method of an unexported field, so it prints a Client held in one by its
	// fields. The client must hold no key there either.
	held := struct{ client llm.Client }{*client}

	subjects := []struct {
		name  string
		value any
	}{
		{"Secret", key},
		{"Config", cfg},
		{"pointer to Config", &cfg},
		{"Client", *client},
		{"pointer to Client", client},
		{"Client in an unexported field", held},
	}
	hexKey := hex.EncodeToString([]byte(testKey))
	// %#v and a wrong verb such as %d don't call String, so a method for every verb is needed.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		for _, subject := range subjects {
			printed := fmt.Sprintf(verb, subject.value)
			require.NotContains(t, printed, testKey, "%s of a %s", verb, subject.name)
			require.NotContains(t, strings.ToLower(printed), hexKey, "%s of a %s", verb, subject.name)
			switch subject.name {
			case "Secret":
				require.Equal(t, redacted, printed, "%s of a Secret", verb)
			case "Config", "pointer to Config":
				require.Contains(t, printed, redacted, "%s of a %s", verb, subject.name)
			}
		}
	}

	for _, value := range []any{cfg, &cfg, key} {
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), testKey)
		require.NotContains(t, strings.ToLower(string(encoded)), hexKey)
		require.Contains(t, string(encoded), redacted)
	}

	require.Equal(t, redacted, key.String())
	encoded, err := key.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, `"`+redacted+`"`, string(encoded))
	// logr's loggers log the result of MarshalLog in place of a value that has one.
	var logged interface{ MarshalLog() any } = key
	require.Equal(t, redacted, logged.MarshalLog())
}

func TestCompleteUnauthorizedDoesNotLeakKey(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := serve(t, refuse(status))
			cfg := configFor(server)
			cfg.APIKey = "secret-key-123"

			_, err := newClient(server, cfg).Complete(t.Context(), ping())

			require.ErrorIs(t, err, llm.ErrUnauthorized)
			requireNoLeak(t, err.Error())
		})
	}
}

func TestEndpointURLThatIsNotValidIsNotQuoted(t *testing.T) {
	// Parsing the URL fails with an error that quotes it, userinfo included.
	cfg := llm.Config{BaseURL: "https://user:pass-word@bad host/v1", Model: testModel, APIKey: testKey}

	_, completeErr := llm.New(cfg).Complete(t.Context(), ping())
	_, probeErr := llm.Probe(t.Context(), cfg, nil)

	for _, err := range []error{completeErr, probeErr} {
		require.ErrorIs(t, err, llm.ErrUnreachable)
		require.NotContains(t, err.Error(), "pass-word")
		require.NotContains(t, err.Error(), "bad host")
	}
}
