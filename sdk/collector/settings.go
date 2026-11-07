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

package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SettingsValidator is a collector that checks its settings beyond what their schema can check.
type SettingsValidator interface {
	// ValidateSettings returns what is wrong with the settings, and nothing when they are valid. It
	// only sees settings that passed their schema, and an empty object for no settings at all.
	ValidateSettings(settings json.RawMessage) []string
}

const (
	// schemaURL names a schema while it compiles.
	schemaURL = "urn:vexplain:collector:schema"
	// noValue is what the settings or the parameters of a request without any are: an empty object,
	// so that a schema decides whether a collector or an operation needs them, and a collector can
	// always decode them.
	noValue = "{}"
)

// settingsCheck checks a collector's settings: against their schema first, and then, if they pass,
// with the collector's own validator, if it has one.
type settingsCheck struct {
	schema    *jsonschema.Schema // nil without a schema
	validator SettingsValidator  // nil without a validator
}

func newSettingsCheck(schema []byte, validator SettingsValidator) (*settingsCheck, error) {
	compiled, err := compileSchema("the settings schema", schema)
	if err != nil {
		return nil, err
	}
	return &settingsCheck{schema: compiled, validator: validator}, nil
}

// problems returns the settings as the collector gets them, and what is wrong with them: that they
// aren't JSON, the violations of their schema, or else what the collector's validator finds.
func (c *settingsCheck) problems(settings []byte) (json.RawMessage, []string) {
	checked, problems := checkJSON("settings", c.schema, settings)
	if len(problems) > 0 || c.validator == nil {
		return checked, problems
	}
	return checked, c.validator.ValidateSettings(checked)
}

// accept returns the settings of a Watch or Invoke as the collector gets them, or InvalidArgument
// with their problems.
func (c *settingsCheck) accept(settings []byte) (json.RawMessage, error) {
	checked, problems := c.problems(settings)
	if len(problems) > 0 {
		return nil, invalidArgument("settings", problems)
	}
	return checked, nil
}

// compileSchema compiles one of a collector's schemas, which name names in errors, or returns nil for
// an empty one. A schema stands alone: the operator compiles it too, from the capabilities, without
// the collector's files. So the compiler loads nothing but the metaschemas, which it holds itself.
func compileSchema(name string, schema []byte) (*jsonschema.Schema, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return nil, fmt.Errorf("%s is not JSON: %w", name, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	if err := compiler.AddResource(schemaURL, doc); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("%s doesn't compile: %w", name, err)
	}
	return compiled, nil
}

// checkJSON returns the settings or the parameters of a request, which what names, as the collector
// gets them, with an empty object for none. It also returns what is wrong with them: that they
// aren't JSON, or the violations of schema, unless it is nil. The violations are sorted, so that the
// same value always gives the same problems.
func checkJSON(what string, schema *jsonschema.Schema, value []byte) (json.RawMessage, []string) {
	if len(bytes.TrimSpace(value)) == 0 {
		value = []byte(noValue)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(value))
	if err != nil {
		return value, []string{"the " + what + " are not JSON"}
	}
	if schema == nil {
		return value, nil
	}
	return value, violations(what, schema.Validate(instance))
}

// invalidArgument is the error of a call whose settings or parameters, which what names, have
// problems.
func invalidArgument(what string, problems []string) error {
	return status.Error(codes.InvalidArgument, "the "+what+" are not valid: "+strings.Join(problems, "; "))
}

// violations lists what a validation of the settings or the parameters, which what names, against
// their schema found: one problem for each violation that has no causes of its own, such as
// "at '/repeat': minimum: got 0, want 1".
func violations(what string, err error) []string {
	if err == nil {
		return nil
	}
	var invalid *jsonschema.ValidationError
	if !errors.As(err, &invalid) {
		return []string{"the " + what + " can't be checked against their schema"}
	}
	problems := leaves(*invalid.DetailedOutput(), nil)
	slices.Sort(problems)
	return slices.Compact(problems)
}

// leaves appends the violations of unit that have no causes of their own.
func leaves(unit jsonschema.OutputUnit, problems []string) []string {
	if unit.Error != nil {
		return append(problems, fmt.Sprintf("at '%s': %s", unit.InstanceLocation, unit.Error.String()))
	}
	for _, cause := range unit.Errors {
		problems = leaves(cause, problems)
	}
	return problems
}
