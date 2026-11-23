package schedule_test

import (
	"testing"
	"time"

	"github.com/bedag/vexplain/internal/schedule"
)

func TestParse(t *testing.T) {
	s, err := schedule.Parse("30 2 * * *")
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	if got, want := s.Next(from), time.Date(2026, 1, 2, 2, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("Next = %v, want %v", got, want)
	}
	for _, bad := range []string{"CRON_TZ=Europe/Zurich 0 * * * *", "@daily", "99 * * * *"} {
		if _, err := schedule.Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}
