package main

import (
	"net/http"

	"github.com/a-h/templ"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	templ.Handler(HomePage()).ServeHTTP(w, r)
}
