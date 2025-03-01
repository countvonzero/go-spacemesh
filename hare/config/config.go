package config

import (
	"time"

	"github.com/spacemeshos/go-spacemesh/common/types"
)

// Config is the configuration of the Hare.
type Config struct {
	N               int           `mapstructure:"hare-committee-size"`   // total number of active parties
	RoundDuration   time.Duration `mapstructure:"hare-round-duration"`   // the duration of a single round
	WakeupDelta     time.Duration `mapstructure:"hare-wakeup-delta"`     // the wakeup delta after tick
	ExpectedLeaders int           `mapstructure:"hare-exp-leaders"`      // the expected number of leaders
	LimitIterations int           `mapstructure:"hare-limit-iterations"` // limit on number of iterations
	LimitConcurrent int           `mapstructure:"hare-limit-concurrent"` // limit number of concurrent CPs
	StopAtxGrading  uint32        `mapstructure:"stop-atx-grading"`

	Hdist uint32

	// If set to non-zero value will disable hare starting at that layer.
	Disable types.LayerID `mapstructure:"disable"`
}

// DefaultConfig returns the default configuration for the hare.
func DefaultConfig() Config {
	return Config{
		N:               10,
		RoundDuration:   10 * time.Second,
		WakeupDelta:     10 * time.Second,
		ExpectedLeaders: 5,
		LimitIterations: 5,
		LimitConcurrent: 5,
		Hdist:           20,
	}
}
