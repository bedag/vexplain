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

import "github.com/bedag/vexplain/internal/metrics"

// The values of the kind label of metrics.LLMTokensTotal.
const (
	kindPrompt     = "prompt"
	kindCompletion = "completion"
)

// PrometheusObserver returns an observer for WithObserver that records every observation in the LLM
// metrics: the request by model and outcome, its duration, and the tokens that the endpoint
// reported. cluster returns the name of this cluster. It is called at each observation, so that the
// series follow a rename.
func PrometheusObserver(cluster func() string) func(Observation) {
	return func(obs Observation) {
		name := cluster()
		metrics.LLMRequestsTotal.WithLabelValues(name, obs.Model, obs.Outcome).Inc()
		metrics.LLMRequestDurationSeconds.WithLabelValues(name, obs.Model).Observe(obs.Duration.Seconds())
		// A counter panics on a negative value, and the endpoint decides what its usage says. A
		// request without usage, such as a failed one, adds no series.
		if obs.Usage.PromptTokens > 0 {
			metrics.LLMTokensTotal.WithLabelValues(name, obs.Model, kindPrompt).Add(float64(obs.Usage.PromptTokens))
		}
		if obs.Usage.CompletionTokens > 0 {
			metrics.LLMTokensTotal.WithLabelValues(name, obs.Model, kindCompletion).Add(float64(obs.Usage.CompletionTokens))
		}
	}
}
