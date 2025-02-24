package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/allanderek/pole-prediction-go/config"
	"github.com/allanderek/pole-prediction-go/datastore"
	"github.com/allanderek/pole-prediction-go/log"
	"github.com/amacneil/dbmate/v2/pkg/dbmate"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/sqlite"
	"github.com/go-chi/jwtauth"

	"database/sql"

	_ "embed"

	_ "modernc.org/sqlite"
)

const (
	env        = "POLEPREDICTION_ENV"
	sessionEnv = "POLEPREDICTION_SESSION"
)

type App struct {
	Environment string
	Config      config.Config
	Queries     *datastore.Queries
	TokenAuth   *jwtauth.JWTAuth
}

var app App

func applyConfig() {
	e := GetEnvironment()
	app.Environment = e
	if e == "" {
		msg := "i dont know enough about my environment to start up"
		log.StartupFailure(
			fmt.Sprintf("missing %s env variable. %s", e, msg),
			errors.New(msg),
		)
	}

	cfg, configFilename := config.GetConfig("./", e)
	app.Config = cfg
	log.Initialise(cfg.LogLevel, cfg.PrettyLogging)

	app.initTokenAuth(cfg.JWTSecret)
	log.StartupMsg(fmt.Sprintf("correctly applied config file: %s", configFilename))
}

func (a *App) initTokenAuth(jwtSecret string) {
	a.TokenAuth = jwtauth.New("HS256", []byte(jwtSecret), nil)
}

func main() {
	applyConfig()

	u, _ := url.Parse("sqlite:debug.predictions.db")
	dbb := dbmate.New(u)

	err := dbb.CreateAndMigrate()
	if err != nil {
		log.StartupFailure("Error migrating DB", err)
	}

	db, err := sql.Open("sqlite", "debug.predictions.db")
	if err != nil {
		log.StartupFailure("Error initialising DB", err)
	}

	app.Queries = datastore.New(db)

	log.StartupMsg("Listening and serving ...")
	http.ListenAndServe(":3003", router())
}

func GetEnvironment() string {
	return strings.ToLower(os.Getenv(env))
}
