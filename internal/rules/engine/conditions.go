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

package engine

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// caseTimeLimit bounds the evaluation of the conditions of one case.
const caseTimeLimit = 100 * time.Millisecond

// Condition is one match condition: a CEL expression over the variables of a case that gives a boolean.
type Condition struct {
	Name, Expression string
}

// Case is what the conditions see, each as a map built from JSON: the finding as rules see it, plus its
// status, rule, justification and epssPermille; the subject; and the impact.
type Case struct {
	Finding, Subject, Impact map[string]any
}

// Conditions are compiled conditions, which a case must all meet.
type Conditions struct {
	names []string
	progs []cel.Program
}

var caseEnvironment = sync.OnceValues(func() (*cel.Env, error) {
	m := cel.MapType(cel.StringType, cel.DynType)
	return cel.NewEnv(
		cel.Variable("finding", m), cel.Variable("subject", m), cel.Variable("impact", m),
		ext.Bindings(), ext.Lists(), ext.Strings(),
		cel.DefaultUTCTimeZone(true),
		cel.ParserExpressionSizeLimit(maxExpressionLength),
	)
})

// CompileConditions compiles the conditions with the guards of rules: the refused calls and the cost limit.
// An error names the condition that is at fault.
func CompileConditions(conds []Condition) (*Conditions, error) {
	env, err := caseEnvironment()
	if err != nil {
		return nil, fmt.Errorf("the CEL environment of cases: %w", err)
	}
	c := &Conditions{}
	for _, cond := range conds {
		prg, err := program(env, fmt.Sprintf("condition %q", cond.Name), cond.Expression, cel.BoolType)
		if err != nil {
			return nil, err
		}
		if slices.Contains(c.names, cond.Name) {
			return nil, fmt.Errorf("the condition %q is named twice", cond.Name)
		}
		c.names = append(c.names, cond.Name)
		c.progs = append(c.progs, prg)
	}
	return c, nil
}

// Match reports whether the case meets every condition. When one doesn't hold, it returns that one's name.
// A condition that fails to evaluate, or gives no boolean, doesn't select the case: it returns its name and the
// error. No conditions match every case.
func (c *Conditions) Match(k Case) (bool, string, error) {
	vars := map[string]any{"finding": k.Finding, "subject": k.Subject, "impact": k.Impact}
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeLimit)
	defer cancel()
	for i, prg := range c.progs {
		out, _, err := prg.ContextEval(ctx, vars)
		if err != nil {
			return false, c.names[i], err
		}
		if held, ok := out.Value().(bool); !ok {
			return false, c.names[i], fmt.Errorf("the condition gives %s, where it must give bool", out.Type())
		} else if !held {
			return false, c.names[i], nil
		}
	}
	return true, "", nil
}
