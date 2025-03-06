package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func router(authHandler *CookieAuthHandler) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(authHandler.AuthMiddleware)

	fs := http.FileServer(http.Dir("static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fs))

	r.Get("/", authHandler.homeHandler)

	// Auth routes
	r.Get("/login", authHandler.LoginHandler)
	r.Post("/login", authHandler.LoginHandler)
	r.Get("/register", authHandler.RegisterHandler)
	r.Post("/register", authHandler.RegisterHandler)
	r.Get("/logout", authHandler.LogoutHandler)
	r.Get("/profile", authHandler.ProfileHandler)

	r.Get("/formulaone/event/{event-id}", authHandler.EventHandler)

	return r
}
