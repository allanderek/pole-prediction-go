package main

import (
	"github.com/go-chi/chi/v5"
	"net/http"
	"strconv"

	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/a-h/templ"
	"github.com/allanderek/pole-prediction-go/auth"
	"github.com/allanderek/pole-prediction-go/datastore"
	"github.com/allanderek/pole-prediction-go/log"
	"strings"
	"time"
)

const currentSeason = "2025"

func (h *CookieAuthHandler) homeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookieInfo := h.verifyCookie(r)

	// Retrieve the list of Formula 1 events for the current season
	events, err := app.Queries.GetFormulaOneEvents(ctx, currentSeason)
	if err != nil {
		log.Error("Could not retrieve the events", err)
		http.Error(w, "Unable to retrieve events", http.StatusInternalServerError)
		return
	}

	// Pass the events to the HomePage template
	templ.Handler(HomePage(cookieInfo, events)).ServeHTTP(w, r)
}

// SessionWithEntrants combines a session with its entrants
type FormulaOneSessionWithEntrants struct {
	Session  datastore.FormulaOneSession
	Entrants []datastore.GetFormulaOneEntrantsBySessionRow
}

// EventData contains all sessions and their entrants for an event
type FormulaOneEventData struct {
	Event    datastore.FormulaOneEventsView
	Sessions []FormulaOneSessionWithEntrants
}

// EventHandler handles displaying a single Formula One event
func (h *CookieAuthHandler) FormulaOneEventHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookieInfo := h.verifyCookie(r)
	eventIDStr := chi.URLParam(r, "event-id")

	eventID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil {
		log.Error("Invalid event ID format", err)
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}

	event, err := app.Queries.GetFormulaOneEvent(ctx, eventID)
	if err != nil {
		log.Error("Could not retrieve the event", err)
		http.Error(w, "Unable to retrieve event", http.StatusInternalServerError)
		return
	}

	sessions, err := app.Queries.GetFormulaOneSessionsByEvent(ctx, eventID)
	if err != nil {
		log.Error(fmt.Sprintf("Could not retrieve the sessions associated with the event: %s", event.Name), err)
		http.Error(w, "Unable to retrieve sessions", http.StatusInternalServerError)
		return
	}

	eventData := FormulaOneEventData{
		Event:    event,
		Sessions: make([]FormulaOneSessionWithEntrants, 0, len(sessions)),
	}

	for _, session := range sessions {
		entrants, err := app.Queries.GetFormulaOneEntrantsBySession(ctx, session.ID)
		if err != nil {
			log.Error(fmt.Sprintf("error fetching entrants for session %d: %w", session.ID), err)
		} else {
			sessionWithEntrants := FormulaOneSessionWithEntrants{
				Session:  session,
				Entrants: entrants,
			}

			eventData.Sessions = append(eventData.Sessions, sessionWithEntrants)
		}
	}

	// Pass the event to the EventPage template
	templ.Handler(FormulaOneEventPage(cookieInfo, eventData)).ServeHTTP(w, r)
}

// FormulaOneSessionHandler handles displaying a single Formula One session with prediction component
func (h *CookieAuthHandler) FormulaOneSessionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookieInfo := h.verifyCookie(r)
	sessionIDStr := chi.URLParam(r, "session-id")

	sessionID, err := strconv.ParseInt(sessionIDStr, 10, 64)
	if err != nil {
		log.Error("Invalid session ID format", err)
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Get session details
	session, err := app.Queries.GetFormulaOneSessionByID(ctx, sessionID)
	if err != nil {
		log.Error("Could not retrieve the session", err)
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	// Get session entrants
	entrants, err := app.Queries.GetFormulaOneEntrantsBySession(ctx, sessionID)
	if err != nil {
		log.Error(fmt.Sprintf("Error fetching entrants for session %d", sessionID), err)
		http.Error(w, "Unable to retrieve session entrants", http.StatusInternalServerError)
		return
	}

	// Combine session and entrants
	sessionData := FormulaOneSessionWithEntrants{
		Session:  session,
		Entrants: entrants,
	}

	// If user is authenticated, try to get their prediction
	var userPrediction []int64
	if cookieInfo.IsAuthenticated {
		userID, err := strconv.ParseInt(cookieInfo.UserID, 10, 64)
		if err == nil {
			// Get user's prediction for this session
			userPrediction, _ = app.Queries.GetUserPredictionEntrantIDsForSession(ctx, datastore.GetUserPredictionEntrantIDsForSessionParams{
				UserID:    userID,
				SessionID: sessionID,
			})
		}
	}

	// Pass the session data to the SessionPage template
	templ.Handler(FormulaOneSessionPage(cookieInfo, sessionData, userPrediction)).ServeHTTP(w, r)
}

// ProfileHandler handles displaying the user's profile
func (h *CookieAuthHandler) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookieInfo := h.verifyCookie(r)
	if !cookieInfo.IsAuthenticated || cookieInfo.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Render the profile template
	templ.Handler(ProfilePage(cookieInfo)).ServeHTTP(w, r)
}

// Secret key for signing cookies - change this to a secure random value
// TOOD: This should be in the config
const cookieSecret = "my-cookie-signing-secret"

// CookieAuthHandler uses cookies for authentication
type CookieAuthHandler struct {
	DB *sql.DB
}

const maxCookieLifeTime = 2592000 // 300 days: 60 * 60 * 24 * 300

// setAuthCookie sets a signed authentication cookie
func (h *CookieAuthHandler) setAuthCookie(w http.ResponseWriter, userId int64, userrole, username, fullname string) {
	// Create cookie value: userId|fullname|timestamp
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	cookieValue := fmt.Sprintf("%d|%s|%s|%s|%s", userId, userrole, username, fullname, timestamp)

	// Sign the cookie value
	signature := h.signCookie(cookieValue)

	// Set the cookie with the signed value
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    cookieValue + "|" + signature,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   maxCookieLifeTime,
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // Set to true in production with HTTPS
	})
}

// signCookie creates a HMAC signature for the cookie value
func (h *CookieAuthHandler) signCookie(value string) string {
	mac := hmac.New(sha256.New, []byte(cookieSecret))
	mac.Write([]byte(value))
	signature := mac.Sum(nil)
	return base64.URLEncoding.EncodeToString(signature)
}

type CookieInfo struct {
	IsAuthenticated bool
	IsAdmin         bool
	UserID          string
	Username        string
	FullName        string
	Timestamp       string
}

// verifyCookie verifies a signed cookie and returns a CookieInfo struct if valid
func (h *CookieAuthHandler) verifyCookie(r *http.Request) CookieInfo {
	cookie, err := r.Cookie("auth")
	if err != nil {
		return CookieInfo{IsAuthenticated: false}
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 6 {
		return CookieInfo{IsAuthenticated: false}
	}

	userId := parts[0]
	userrole := parts[1]
	username := parts[2]
	fullname := parts[3]
	timestamp := parts[4]
	signature := parts[5]

	// Verify the signature
	cookieValue := fmt.Sprintf("%s|%s|%s|%s|%s", userId, userrole, username, fullname, timestamp)
	expectedSignature := h.signCookie(cookieValue)

	if signature != expectedSignature {
		return CookieInfo{IsAuthenticated: false}
	}

	// Verify cookie isn't too old (optional)
	var ts int64
	fmt.Sscanf(timestamp, "%d", &ts)
	if time.Now().Unix()-ts > maxCookieLifeTime {
		return CookieInfo{IsAuthenticated: false}
	}

	return CookieInfo{
		IsAuthenticated: true,
		IsAdmin:         userrole == "admin",
		UserID:          userId,
		Username:        username,
		FullName:        fullname,
		Timestamp:       timestamp,
	}
}

// clearAuthCookie clears the authentication cookie
func (h *CookieAuthHandler) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

// Middleware to check if user is authenticated
func (h *CookieAuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow access to login and register pages
		if r.URL.Path == "/login" || r.URL.Path == "/register" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if user is authenticated
		cookieInfo := h.verifyCookie(r)
		if !cookieInfo.IsAuthenticated || cookieInfo.UserID == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// User is authenticated, proceed
		next.ServeHTTP(w, r)
	})
}

// LoginHandler handles user login with cookies
func (h *CookieAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookieInfo := h.verifyCookie(r)
	// Display login form for GET requests
	if r.Method == http.MethodGet {
		// Render the login template
		templ.Handler(LoginPage("", cookieInfo)).ServeHTTP(w, r)
		return
	}

	// Process login for POST requests
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var error string

		user, err := app.Queries.GetUser(ctx, username)

		if err != nil {
			if err == sql.ErrNoRows {
				error = "Incorrect username"
			} else {
				error = "Database error, please try again"
			}
		} else {
			// Verify the password using our auth package
			if !auth.VerifyPassword(password, user.Password) {
				error = "Incorrect password"
			}
		}

		if error == "" {
			// Login successful, set auth cookie
			userrole := "user"
			if user.Admin.Valid && user.Admin.Int64 == 1 {
				userrole = "admin"
			}

			h.setAuthCookie(w, user.ID, userrole, username, user.Fullname)

			// Redirect to home page
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Login failed, display error
		templ.Handler(LoginPage(error, cookieInfo)).ServeHTTP(w, r)
		return
	}

	// Method not allowed for anything else
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// RegisterHandler handles user registration
func (h *CookieAuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Display registration form for GET requests
	cookieInfo := h.verifyCookie(r)
	if r.Method == http.MethodGet {
		templ.Handler(RegisterPage("", cookieInfo)).ServeHTTP(w, r)
		return
	}

	// Process registration for POST requests
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		fullname := r.FormValue("fullname")

		ctx := r.Context()
		var error string

		// Validate inputs
		if username == "" {
			error = "Username required"
		} else if password == "" {
			error = "Password required"
		} else {
			// Check if username already exists
			existing, err := app.Queries.UserExists(ctx, username)
			if err == nil && existing > 0 {
				error = "Username " + username + " registered already"
			}
		}

		if error == "" {
			// Use default username as fullname if not provided
			if fullname == "" {
				fullname = username
			}

			// Hash the password
			hashedPassword := auth.HashPassword(password)

			toAdd := datastore.AddNewUserParams{
				Fullname: fullname,
				Username: username,
				Password: hashedPassword,
			}

			err := app.Queries.AddNewUser(ctx, toAdd)

			if err != nil {
				error = "Database error, please try again"
			} else {
				// Registration successful, redirect to login
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}

		// Registration failed, display error
		templ.Handler(RegisterPage(error, cookieInfo)).ServeHTTP(w, r)
		return
	}

	// Method not allowed for anything else
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// LogoutHandler handles user logout
func (h *CookieAuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	h.clearAuthCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
