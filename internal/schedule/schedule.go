// Package schedule parses the cron expressions of collectors' and investigations' schedules.
package schedule

import (
	"errors"
	"strings"

	"github.com/robfig/cron/v3"
)

// parser parses the five fields of a standard cron expression, minute, hour, day of month, month and day of week,
// as Kubernetes' CronJob does, and no descriptor such as @daily.
var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// Parse parses a schedule's cron expression, which runs in UTC. It refuses a time zone, as TZ= or CRON_TZ=, which
// the parser would take otherwise: schedules run in UTC, and Kubernetes refuses a time zone in a CronJob's schedule in
// the same way.
func Parse(expression string) (cron.Schedule, error) {
	if strings.Contains(expression, "TZ") {
		return nil, errors.New("it names a time zone, and schedules run in UTC")
	}
	return parser.Parse(expression)
}
