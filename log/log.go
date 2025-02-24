package log

import (
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

func Initialise(logLevel int, prettyLogging bool) {
	zerolog.SetGlobalLevel(zerolog.Level(logLevel))
	zerolog.DurationFieldUnit = time.Second
	zerolog.LevelFieldName = "severity"
	zerolog.TimestampFieldName = "timestamp"
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	if prettyLogging {
		SetPrettyLogging()
	}
}

func SetPrettyLogging() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func StartupFailure(msg string, err error) {
	log.Fatal().Stack().Err(err).Msg(msg)
}

func StartupMsg(msg string) {
	log.Info().Msg(msg)
}

func Error(msg string, err error) {
	log.Error().Stack().Err(err).Msg(msg)
}

func Debug(msg string) {
	log.Debug().Msg(msg)
}

func DebugF(template string, val any) {
	log.Debug().Msg(fmt.Sprintf(template, val))
}
