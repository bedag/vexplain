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

package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// The bounds of what status.capabilities records, as the Collector's schema sets them.
const (
	maxTypes               = 32
	maxTypeLength          = 253
	maxOperations          = 16
	maxOperationNameLength = 63
	maxSchedules           = 8
	maxScheduleCronLength  = 128
	maxSources             = 8
	maxVersionLength       = 128
	// maxQuotedLength is how much of a name that a collector chose a message repeats.
	maxQuotedLength = 64
)

// The roles and scopes of the collector API, by those of a Collector's status.
var (
	collectorRoles = map[collectorv1alpha1.Role]configv1alpha1.CollectorRole{
		collectorv1alpha1.Role_ROLE_SPOKE: configv1alpha1.CollectorRoleSpoke,
		collectorv1alpha1.Role_ROLE_HUB:   configv1alpha1.CollectorRoleHub,
	}
	evidenceScopes = map[collectorv1alpha1.Scope]configv1alpha1.EvidenceScope{
		collectorv1alpha1.Scope_SCOPE_SPOKE: configv1alpha1.EvidenceScopeSpoke,
		collectorv1alpha1.Scope_SCOPE_HUB:   configv1alpha1.EvidenceScopeHub,
	}
)

// checkInfo returns the version of a collector's answer to GetInfo. It refuses, for IncompatibleAPI, an answer that
// doesn't list the version of the collector API that this operator speaks, and, for PackageInvalid, one without a name
// or a version, or with a version that the status can't hold.
func checkInfo(info *collectorv1alpha1.GetInfoResponse) (string, *refusal) {
	if !slices.Contains(info.GetApiVersions(), apiVersion) {
		return "", refuse(configv1alpha1.ReasonIncompatibleAPI,
			"The collector speaks %s of the collector API, and this operator speaks %s.", spoken(info.GetApiVersions()), apiVersion)
	}
	version := info.GetVersion()
	switch {
	case info.GetName() == "":
		return "", refuse(configv1alpha1.ReasonPackageInvalid, "The collector's answer to GetInfo gives no name.")
	case version == "":
		return "", refuse(configv1alpha1.ReasonPackageInvalid, "The collector's answer to GetInfo gives no version.")
	case utf8.RuneCountInString(version) > maxVersionLength || text.Printable(version) != version:
		return "", refuse(configv1alpha1.ReasonPackageInvalid,
			"The collector's answer to GetInfo gives the version %s, and a version is at most %d printable characters.",
			quote(version), maxVersionLength)
	}
	return version, nil
}

// sourcesOf returns the sources of a collector's answer to GetInfo, sorted by name, with the time of each built to
// whole seconds, as the API keeps them, so that an answer that doesn't change doesn't change the status. It refuses,
// for PackageInvalid, an answer with more sources than the status holds, and a source whose name or version the
// status can't hold.
func sourcesOf(info *collectorv1alpha1.GetInfoResponse) ([]configv1alpha1.CollectorSource, *refusal) {
	sources := info.GetSources()
	if len(sources) > maxSources {
		return nil, refuse(configv1alpha1.ReasonPackageInvalid,
			"The collector's answer to GetInfo lists %d sources, more than the %d that the status holds.", len(sources), maxSources)
	}
	var recorded []configv1alpha1.CollectorSource
	for _, source := range sources {
		name, version := source.GetName(), source.GetVersion()
		var problem string
		switch {
		case name == "":
			problem = "a source without a name"
		case utf8.RuneCountInString(name) > maxOperationNameLength || text.Printable(name) != name:
			problem = fmt.Sprintf("the source %s has a name that isn't at most %d printable characters", quote(name),
				maxOperationNameLength)
		case slices.ContainsFunc(recorded, func(s configv1alpha1.CollectorSource) bool { return s.Name == name }):
			problem = fmt.Sprintf("the source %s twice", quote(name))
		case version == "":
			problem = fmt.Sprintf("the source %s has no version", quote(name))
		case utf8.RuneCountInString(version) > maxVersionLength || text.Printable(version) != version:
			problem = fmt.Sprintf("the source %s has a version that isn't at most %d printable characters", quote(name),
				maxVersionLength)
		}
		if problem != "" {
			return nil, refuse(configv1alpha1.ReasonPackageInvalid, "The collector's answer to GetInfo is malformed: %s.",
				problem)
		}
		recorded = append(recorded, configv1alpha1.CollectorSource{Name: name, Version: version,
			BuiltTime: builtTime(source)})
	}
	slices.SortFunc(recorded, func(a, b configv1alpha1.CollectorSource) int { return strings.Compare(a.Name, b.Name) })
	return recorded, nil
}

// builtTime returns the time that a source says its data was built, in whole seconds, and nil for a source that says
// none.
func builtTime(source *collectorv1alpha1.Source) *metav1.Time {
	if source.GetBuiltTime() == nil {
		return nil
	}
	built := metav1.NewTime(source.GetBuiltTime().AsTime().Truncate(time.Second))
	return &built
}

// spoken lists the versions of the API that a collector speaks, for a message.
func spoken(versions []string) string {
	if len(versions) == 0 {
		return "no version"
	}
	const maxShown = 8
	shown := make([]string, 0, maxShown)
	for _, v := range versions[:min(len(versions), maxShown)] {
		shown = append(shown, quote(v))
	}
	listed := "the versions " + strings.Join(shown, ", ")
	if more := len(versions) - maxShown; more > 0 {
		listed += fmt.Sprintf(", and %d more", more)
	}
	return listed
}

// quote returns a name that a collector chose, quoted as Go quotes a string, which escapes what isn't printable, and
// cut to maxQuotedLength characters first.
func quote(name string) string {
	return strconv.Quote(text.CutChars(name, maxQuotedLength))
}

// declarations is what the deployer needs of a collector's capabilities that status.capabilities doesn't record: the
// compiled schema of its settings, nil without one, and the checks of the permissions that it declares.
type declarations struct {
	settings    *jsonschema.Schema
	permissions []authorizationv1.ResourceAttributes
}

// capabilitiesOf checks a collector's answer to GetCapabilities, and returns what status.capabilities records of it,
// each list sorted, so that the status doesn't change with the order of an answer. It returns an error instead, which
// says what is malformed, for an answer that the Collector's schema would refuse, and for one that vexplain can't use:
// a role or a scope that this version doesn't know, a type of evidence outside the pattern of types, a produced type
// without a schema (decision 0032), a schema that doesn't compile, an operation's name that isn't printable, more than
// the status holds, or more permissions than the deployer checks. Nothing of such an answer is recorded.
func capabilitiesOf(answer *collectorv1alpha1.GetCapabilitiesResponse, namespace string) (
	*configv1alpha1.CollectorCapabilities, *declarations, error) {
	capabilities := &configv1alpha1.CollectorCapabilities{Watch: configv1alpha1.CollectorWatchNotSupported}
	if answer.GetWatches() {
		capabilities.Watch = configv1alpha1.CollectorWatchSupported
	}
	var err error
	if capabilities.Roles, err = rolesOf(answer.GetRoles()); err != nil {
		return nil, nil, err
	}
	if capabilities.Produces, err = producedTypesOf(answer.GetProduces()); err != nil {
		return nil, nil, err
	}
	if capabilities.Consumes, err = typesOf("the consumed types", answer.GetConsumes()); err != nil {
		return nil, nil, err
	}
	if capabilities.Operations, err = operationsOf(answer.GetOperations()); err != nil {
		return nil, nil, err
	}
	if capabilities.Schedules, err = schedulesOf(answer.GetSchedules()); err != nil {
		return nil, nil, err
	}
	settings, err := compileSchema(answer.GetSettingsSchema())
	if err != nil {
		return nil, nil, fmt.Errorf("the settings schema %w", err)
	}
	permissions, err := permissionChecks(answer.GetPermissions(), namespace)
	if err != nil {
		return nil, nil, err
	}
	return capabilities, &declarations{settings: settings, permissions: permissions}, nil
}

// rolesOf returns the roles of an answer, sorted.
func rolesOf(roles []collectorv1alpha1.Role) ([]configv1alpha1.CollectorRole, error) {
	var recorded []configv1alpha1.CollectorRole
	for _, role := range roles {
		known, ok := collectorRoles[role]
		switch {
		case !ok:
			return nil, fmt.Errorf("GetCapabilities lists the role %s, and a role is ROLE_SPOKE or ROLE_HUB", role)
		case slices.Contains(recorded, known):
			return nil, fmt.Errorf("GetCapabilities lists the role %s twice", role)
		}
		recorded = append(recorded, known)
	}
	slices.Sort(recorded)
	return recorded, nil
}

// producedTypesOf returns the produced types of an answer, sorted by type. Each has a scope and a schema that compiles.
func producedTypesOf(produced []*collectorv1alpha1.EvidenceType) ([]configv1alpha1.ProducedType, error) {
	if len(produced) > maxTypes {
		return nil, fmt.Errorf("the produced types are %d, more than the %d that the status holds", len(produced), maxTypes)
	}
	recorded := make([]configv1alpha1.ProducedType, 0, len(produced))
	for _, p := range produced {
		name := p.GetType()
		if err := checkType(name); err != nil {
			return nil, fmt.Errorf("the produced types: %w", err)
		}
		scope, ok := evidenceScopes[p.GetScope()]
		switch {
		case slices.ContainsFunc(recorded, func(t configv1alpha1.ProducedType) bool { return t.Type == name }):
			return nil, fmt.Errorf("the produced types list %s twice", quote(name))
		case !ok:
			return nil, fmt.Errorf("the produced type %s has the scope %s, and a scope is SCOPE_SPOKE or SCOPE_HUB",
				quote(name), p.GetScope())
		case len(p.GetSchema()) == 0:
			return nil, fmt.Errorf("the produced type %s has no schema, and each type describes its data in a JSON Schema",
				quote(name))
		}
		if _, err := compileSchema(p.GetSchema()); err != nil {
			return nil, fmt.Errorf("the schema of the produced type %s %w", quote(name), err)
		}
		recorded = append(recorded, configv1alpha1.ProducedType{Type: name, Scope: scope})
	}
	slices.SortFunc(recorded, func(a, b configv1alpha1.ProducedType) int { return strings.Compare(a.Type, b.Type) })
	return recorded, nil
}

// typesOf returns a list of types of an answer, which list names, sorted.
func typesOf(list string, types []string) ([]string, error) {
	if len(types) > maxTypes {
		return nil, fmt.Errorf("%s are %d, more than the %d that the status holds", list, len(types), maxTypes)
	}
	for i, name := range types {
		if err := checkType(name); err != nil {
			return nil, fmt.Errorf("%s: %w", list, err)
		}
		if slices.Contains(types[:i], name) {
			return nil, fmt.Errorf("%s list %s twice", list, quote(name))
		}
	}
	recorded := slices.Clone(types)
	slices.Sort(recorded)
	return recorded, nil
}

// checkType says why name can't be the name of a type of evidence, or nil when it can.
func checkType(name string) error {
	switch {
	case name == "":
		return errors.New("a type without a name")
	case len(name) > maxTypeLength || !sdkevidence.ValidType(name):
		return fmt.Errorf("the type %s isn't reverse-DNS with a version, of at most %d characters", quote(name), maxTypeLength)
	}
	return nil
}

// operationsOf returns the operations of an answer, sorted by name, with their types sorted. Each runs in a role that
// this version knows, and its parameter schema compiles.
func operationsOf(operations []*collectorv1alpha1.Operation) ([]configv1alpha1.CollectorOperation, error) {
	if len(operations) > maxOperations {
		return nil, fmt.Errorf("the operations are %d, more than the %d that the status holds", len(operations), maxOperations)
	}
	recorded := make([]configv1alpha1.CollectorOperation, 0, len(operations))
	for _, op := range operations {
		name := op.GetName()
		_, knownRole := collectorRoles[op.GetRole()]
		switch {
		case name == "":
			return nil, errors.New("GetCapabilities declares an operation without a name")
		case utf8.RuneCountInString(name) > maxOperationNameLength:
			return nil, fmt.Errorf("the operation %s has a name of more than %d characters", quote(name), maxOperationNameLength)
		case text.Printable(name) != name:
			return nil, fmt.Errorf("the name of the operation %s isn't printable", quote(name))
		case slices.ContainsFunc(recorded, func(o configv1alpha1.CollectorOperation) bool { return o.Name == name }):
			return nil, fmt.Errorf("GetCapabilities declares the operation %s twice", quote(name))
		case !knownRole:
			return nil, fmt.Errorf("the operation %s runs in the role %s, and a role is ROLE_SPOKE or ROLE_HUB",
				quote(name), op.GetRole())
		}
		produces, err := typesOf("the types that the operation "+quote(name)+" produces", op.GetProduces())
		if err != nil {
			return nil, err
		}
		consumes, err := typesOf("the types that the operation "+quote(name)+" consumes", op.GetConsumes())
		if err != nil {
			return nil, err
		}
		if _, err := compileSchema(op.GetParameterSchema()); err != nil {
			return nil, fmt.Errorf("the parameter schema of the operation %s %w", quote(name), err)
		}
		recorded = append(recorded, configv1alpha1.CollectorOperation{Name: name, Produces: produces, Consumes: consumes})
	}
	slices.SortFunc(recorded, func(a, b configv1alpha1.CollectorOperation) int { return strings.Compare(a.Name, b.Name) })
	return recorded, nil
}

// schedulesOf returns the schedules of an answer, sorted by name. Each has a printable name of its own and a cron
// expression that the status can hold. The operator parses the expression when it runs the schedule.
func schedulesOf(schedules []*collectorv1alpha1.Schedule) ([]configv1alpha1.CollectorSchedule, error) {
	if len(schedules) > maxSchedules {
		return nil, fmt.Errorf("the schedules are %d, more than the %d that the status holds", len(schedules), maxSchedules)
	}
	var recorded []configv1alpha1.CollectorSchedule
	for _, schedule := range schedules {
		name, cron := schedule.GetName(), schedule.GetCron()
		switch {
		case name == "":
			return nil, errors.New("GetCapabilities declares a schedule without a name")
		case utf8.RuneCountInString(name) > maxOperationNameLength || text.Printable(name) != name:
			return nil, fmt.Errorf("the name of the schedule %s isn't at most %d printable characters", quote(name),
				maxOperationNameLength)
		case slices.ContainsFunc(recorded, func(s configv1alpha1.CollectorSchedule) bool { return s.Name == name }):
			return nil, fmt.Errorf("GetCapabilities declares the schedule %s twice", quote(name))
		case cron == "":
			return nil, fmt.Errorf("the schedule %s has no cron expression", quote(name))
		case utf8.RuneCountInString(cron) > maxScheduleCronLength || text.Printable(cron) != cron:
			return nil, fmt.Errorf("the cron expression of the schedule %s isn't at most %d printable characters",
				quote(name), maxScheduleCronLength)
		}
		recorded = append(recorded, configv1alpha1.CollectorSchedule{Name: name, Cron: cron})
	}
	slices.SortFunc(recorded, func(a, b configv1alpha1.CollectorSchedule) int { return strings.Compare(a.Name, b.Name) })
	return recorded, nil
}

// schemaURL names a collector's schema while it compiles.
const schemaURL = "urn:vexplain:collector:schema"

// compileSchema compiles a JSON Schema that a collector declares, or returns nil for none. The compiler loads nothing
// but the metaschemas that it holds itself, so a schema stands alone, as the SDK requires, and compiling it never makes
// the operator fetch anything. An error says what is wrong, as the end of a sentence about the schema.
func compileSchema(schema []byte) (*jsonschema.Schema, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return nil, fmt.Errorf("isn't JSON: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	if err := compiler.AddResource(schemaURL, doc); err != nil {
		return nil, fmt.Errorf("doesn't compile: %w", err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("doesn't compile: %w", err)
	}
	return compiled, nil
}

// settingsProblems checks the settings of obj against the collector's settings schema, and then, when they pass it,
// with the collector's own check, which may rely on the schema. It returns what is wrong with them, and an error when
// the collector's check fails.
func (r *CollectorReconciler) settingsProblems(ctx context.Context, obj *configv1alpha1.Collector,
	schema *jsonschema.Schema) ([]string, error) {
	var settings []byte
	if obj.Spec.Settings != nil {
		settings = obj.Spec.Settings.Raw
	}
	if problems := schemaProblems(schema, settings); len(problems) > 0 {
		return problems, nil
	}
	return within(ctx, func(ctx context.Context) ([]string, error) {
		return r.Pool.ValidateSettings(ctx, obj.Name, settings)
	})
}

// schemaProblems returns the violations of schema by settings, sorted, as the SDK's server reports them: one for each
// that has no causes of its own, such as "at '/greeting': got number, want string". No settings are an empty object.
func schemaProblems(schema *jsonschema.Schema, settings []byte) []string {
	if len(bytes.TrimSpace(settings)) == 0 {
		settings = []byte("{}")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(settings))
	if err != nil {
		return []string{"the settings are not JSON"}
	}
	if schema == nil {
		return nil
	}
	err = schema.Validate(doc)
	if err == nil {
		return nil
	}
	var invalid *jsonschema.ValidationError
	if !errors.As(err, &invalid) {
		return []string{"the settings can't be checked against their schema"}
	}
	problems := violations(*invalid.DetailedOutput(), nil)
	slices.Sort(problems)
	return slices.Compact(problems)
}

// violations appends the violations of unit that have no causes of their own.
func violations(unit jsonschema.OutputUnit, problems []string) []string {
	if unit.Error != nil {
		return append(problems, fmt.Sprintf("at '%s': %s", unit.InstanceLocation, unit.Error.String()))
	}
	for _, cause := range unit.Errors {
		problems = violations(cause, problems)
	}
	return problems
}
