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
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The CEL environment that a rule is written in. A rule sees two kinds of variable:
//   - finding: the finding, with the fields of a match, named as its JSON names them, such as
//     finding.packageID and finding.knownExploited
//   - one variable for each input, named after it: a map with the input's data, decoded from JSON,
//     its coverage, its time and its source. An input without coverage has no coverage key, so that
//     a rule that reads it fails, and one that checks has() can tell.
//
// Besides CEL's standard library, a rule can use cel-go's extensions for bindings, cel.bind, for lists,
// such as sortBy, and for strings, such as join. Times are read in UTC, so that a rule decides the same
// wherever the operator runs.

const (
	// findingVariable is the variable that holds the finding.
	findingVariable = "finding"
	// matchType is the name that CEL gives the Go type of a finding: its package, then its name.
	matchType = "evidence.Match"

	// The keys of an input's variable.
	dataKey     = "data"
	coverageKey = "coverage"
	timeKey     = "time"
	sourceKey   = "source"

	// costLimit is the most that one evaluation of an expression may cost, in CEL's units. It bounds
	// the time that one finding can take, whatever the evidence holds. An evaluation that would cost
	// more fails, as an error does.
	costLimit = 1_000_000
	// maxExpressionLength is the most characters of an expression, as the schema of a Rule allows.
	maxExpressionLength = 4096
)

// inputName is the pattern of an input's name, as the schema of a Rule has it: a CEL identifier.
var inputName = regexp.MustCompile(`^[a-z][a-zA-Z0-9]{0,62}$`)

// reservedWords are CEL's literals, its operator in, and the words that it reserves. The schema's
// pattern lets them through, but no expression can name a variable that is called like one, and the
// literals would stand for themselves.
var reservedWords = []string{
	"true", "false", "null", "in", "as", "break", "const", "continue", "else", "for", "function", "if",
	"import", "let", "loop", "package", "namespace", "return", "var", "void", "while",
}

// baseEnvironment is what the environment of every rule has: the finding and the libraries. The
// inputs differ from rule to rule, so each rule's environment extends this one with its own.
var baseEnvironment = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[evidence.Match](), ext.ParseStructTag("json")),
		cel.Variable(findingVariable, cel.ObjectType(matchType)),
		ext.Bindings(),
		ext.Lists(),
		ext.Strings(),
		cel.DefaultUTCTimeZone(true),
		cel.ParserExpressionSizeLimit(maxExpressionLength),
	)
})

// environment returns the environment of a rule with the given inputs, and the names of the inputs,
// sorted.
func environment(inputs []configv1alpha1.RuleInput) (*cel.Env, []string, error) {
	base, err := baseEnvironment()
	if err != nil {
		return nil, nil, fmt.Errorf("the CEL environment of rules: %w", err)
	}
	names := make([]string, 0, len(inputs))
	variables := make([]cel.EnvOption, 0, len(inputs))
	for _, in := range inputs {
		if err := checkInputName(in.Name, names); err != nil {
			return nil, nil, err
		}
		names = append(names, in.Name)
		variables = append(variables, cel.Variable(in.Name, cel.MapType(cel.StringType, cel.DynType)))
	}
	env, err := base.Extend(variables...)
	if err != nil {
		return nil, nil, fmt.Errorf("the inputs: %w", err)
	}
	slices.Sort(names)
	return env, names, nil
}

// checkInputName returns an error for a name that no input can have: one that isn't a CEL
// identifier, the name of the finding, a reserved word, or the name of an earlier input.
func checkInputName(name string, earlier []string) error {
	switch {
	case !inputName.MatchString(name):
		return fmt.Errorf("the input name %q isn't a CEL identifier of at most 63 characters", name)
	case name == findingVariable:
		return fmt.Errorf("the input name %q would hide the finding", name)
	case slices.Contains(reservedWords, name):
		return fmt.Errorf("the input name %q is reserved in CEL", name)
	case slices.Contains(earlier, name):
		return fmt.Errorf("two inputs are named %q", name)
	}
	return nil
}

// variable returns what a rule sees of an input, as CEL's values. A coverage is a whole number, so that
// a rule can compare it, and print it, as one.
func variable(in Input) ref.Val {
	v := map[ref.Val]ref.Val{
		types.String(dataKey):   value(in.Data),
		types.String(timeKey):   types.Timestamp{Time: in.Time},
		types.String(sourceKey): types.String(in.Source),
	}
	if in.Coverage != nil {
		v[types.String(coverageKey)] = types.Int(*in.Coverage)
	}
	return types.NewRefValMap(types.DefaultTypeAdapter, v)
}

// value returns data decoded from JSON as CEL's values: each object as a map, each array as a list, and
// the rest as CEL converts it. CEL would otherwise convert an object or an array each time that a rule
// reads it, which a rule that goes through a list does for every item and every finding.
func value(data any) ref.Val {
	switch data := data.(type) {
	case map[string]any:
		m := make(map[ref.Val]ref.Val, len(data))
		for k, v := range data {
			m[types.String(k)] = value(v)
		}
		return types.NewRefValMap(types.DefaultTypeAdapter, m)
	case []any:
		l := make([]ref.Val, len(data))
		for i, v := range data {
			l[i] = value(v)
		}
		return types.NewRefValList(types.DefaultTypeAdapter, l)
	}
	return types.DefaultTypeAdapter.NativeToValue(data)
}
