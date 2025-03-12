package config

import (
	"fmt"
	"github.com/allanderek/pole-prediction-go/lib/file"
	"github.com/allanderek/pole-prediction-go/log"
	"path/filepath"
)

type Config struct {
	LogLevel      int    `json:"logLevel"`
	PrettyLogging bool   `json:"prettyLogging"`
	JWTSecret     string `json:"jwtSecret"`
	DBFilepath    string `json:"dbFilepath"`
	Port          int    `json:"port"`
}

func GetConfig(projectRoot, environment string) (Config, string) {
	var c Config

	configFilename := fmt.Sprintf("config.%s.json", environment)
	configFilepath := filepath.Join(projectRoot, configFilename)
	if err := file.ReadAndMarshallFile(configFilepath, &c); err != nil {
		log.StartupFailure("Error applying APP configuration file", err)
	}

	return c, configFilename
}
