package main

import (
	"context"
	"net/http"

	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/a-h/templ"
	"github.com/allanderek/pole-prediction-go/auth"
	"strings"
	"time"
)

func (h *CookieAuthHandler) homeHandler(w http.ResponseWriter, r *http.Request) {
	cookieInfo, isAuthenticated := h.verifyCookie(r)
	templ.Handler(HomePage(isAuthenticated, cookieInfo.FullName)).ServeHTTP(w, r)
}

// ProfileHandler handles displaying the user's profile
func (h *CookieAuthHandler) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookieInfo, isAuthenticated := h.verifyCookie(r)
	if !isAuthenticated || cookieInfo.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Render the profile template
	templ.Handler(ProfilePage(cookieInfo.UserID, cookieInfo.FullName)).ServeHTTP(w, r)
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
func (h *CookieAuthHandler) setAuthCookie(w http.ResponseWriter, userId int64, fullname string) {
	// Create cookie value: userId|fullname|timestamp
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	cookieValue := fmt.Sprintf("%d|%s|%s", userId, fullname, timestamp)

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
	UserID    string
	FullName  string
	Timestamp string
}

// verifyCookie verifies a signed cookie and returns a CookieInfo struct if valid
func (h *CookieAuthHandler) verifyCookie(r *http.Request) (CookieInfo, bool) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		return CookieInfo{}, false
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 4 {
		return CookieInfo{}, false
	}

	userId := parts[0]
	fullname := parts[1]
	timestamp := parts[2]
	signature := parts[3]

	// Verify the signature
	cookieValue := fmt.Sprintf("%s|%s|%s", userId, fullname, timestamp)
	expectedSignature := h.signCookie(cookieValue)

	if signature != expectedSignature {
		return CookieInfo{}, false
	}

	// Verify cookie isn't too old (optional)
	var ts int64
	fmt.Sscanf(timestamp, "%d", &ts)
	if time.Now().Unix()-ts > maxCookieLifeTime {
		return CookieInfo{}, false
	}

	return CookieInfo{userId, fullname, timestamp}, true
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
		cookieInfo, ok := h.verifyCookie(r)
		if !ok || cookieInfo.UserID == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// User is authenticated, proceed
		next.ServeHTTP(w, r)
	})
}

// LoginHandler handles user login with cookies
func (h *CookieAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	cookieInfo, isAuthenticated := h.verifyCookie(r)
	// Display login form for GET requests
	if r.Method == http.MethodGet {
		// Render the login template
		templ.Handler(LoginPage("", isAuthenticated, cookieInfo.FullName)).ServeHTTP(w, r)
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
			h.setAuthCookie(w, user.ID, user.Fullname)

			// Redirect to home page
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Login failed, display error
		templ.Handler(LoginPage(error, isAuthenticated, cookieInfo.FullName)).ServeHTTP(w, r)
		return
	}

	// Method not allowed for anything else
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// RegisterHandler handles user registration
func (h *CookieAuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Display registration form for GET requests
	cookieInfo, isAuthenticated := h.verifyCookie(r)
	if r.Method == http.MethodGet {
		templ.Handler(RegisterPage("", isAuthenticated, cookieInfo.FullName)).ServeHTTP(w, r)
		return
	}

	// Process registration for POST requests
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		fullname := r.FormValue("fullname")

		var error string

		// Validate inputs
		if username == "" {
			error = "Username required"
		} else if password == "" {
			error = "Password required"
		} else {
			// Check if username already exists
			ctx := context.Background()
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

			// Insert the new user
			_, err := h.DB.Exec("INSERT INTO users (fullname, username, password) VALUES (?, ?, ?)",
				fullname, username, hashedPassword)

			if err != nil {
				error = "Database error, please try again"
			} else {
				// Registration successful, redirect to login
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}

		// Registration failed, display error
		templ.Handler(RegisterPage(error, isAuthenticated, cookieInfo.FullName)).ServeHTTP(w, r)
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
