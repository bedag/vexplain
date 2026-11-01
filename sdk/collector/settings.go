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
	// settingsURL names the settings schema while it compiles.
	settingsURL = "urn:vexplain:collector:settings"
	// notJSON is the problem of settings that aren't JSON.
	notJSON = "the settings are not JSON"
	// noSettings are the settings of a request without any: an empty object, so that a schema
	// decides whether a collector needs settings, and a collector can always decode them.
	noSettings = "{}"
)

// settingsCheck checks a collector's settings: against their schema first, and then, if they pass,
// with the collector's own validator, if it has one.
type settingsCheck struct {
	schema    *jsonschema.Schema // nil without a schema
	validator SettingsValidator  // nil without a validator
}

// newSettingsCheck compiles the schema, unless it is empty. The schema must stand alone: the
// operator compiles it too, from the capabilities, without the collector's files. So the compiler
// loads nothing but the metaschemas, which it holds itself.
func newSettingsCheck(schema []byte, validator SettingsValidator) (*settingsCheck, error) {
	check := &settingsCheck{validator: validator}
	if len(schema) == 0 {
		return check, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return nil, fmt.Errorf("the settings schema is not JSON: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	if err := compiler.AddResource(settingsURL, doc); err != nil {
		return nil, fmt.Errorf("the settings schema: %w", err)
	}
	if check.schema, err = compiler.Compile(settingsURL); err != nil {
		return nil, fmt.Errorf("the settings schema doesn't compile: %w", err)
	}
	return check, nil
}

// problems returns the settings as the collector gets them, and what is wrong with them: the
// violations of their schema, or else what the collector's validator finds. A schema's violations
// are sorted, so that the same settings always give the same problems.
func (c *settingsCheck) problems(settings []byte) (json.RawMessage, []string) {
	if len(bytes.TrimSpace(settings)) == 0 {
		settings = []byte(noSettings)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(settings))
	if err != nil {
		return settings, []string{notJSON}
	}
	if c.schema != nil {
		if problems := violations(c.schema.Validate(instance)); len(problems) > 0 {
			return settings, problems
		}
	}
	if c.validator == nil {
		return settings, nil
	}
	return settings, c.validator.ValidateSettings(settings)
}

// accept returns the settings of a Watch or Invoke as the collector gets them, or InvalidArgument
// with their problems.
func (c *settingsCheck) accept(settings []byte) (json.RawMessage, error) {
	checked, problems := c.problems(settings)
	if len(problems) > 0 {
		return nil, status.Error(codes.InvalidArgument, "the settings are not valid: "+strings.Join(problems, "; "))
	}
	return checked, nil
}

// violations lists what a validation against a schema found, one problem for each violation that
// has no causes of its own, such as "at '/repeat': minimum: got 0, want 1".
func violations(err error) []string {
	if err == nil {
		return nil
	}
	var invalid *jsonschema.ValidationError
	if !errors.As(err, &invalid) {
		return []string{"the settings can't be checked against their schema"}
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
