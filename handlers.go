package main

import (
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

func homeHandler(w http.ResponseWriter, r *http.Request) {
	userId, fullname, isAuthenticated := authHandler.verifyCookie(r)
	templ.Handler(HomePage(isAuthenticated, fullname)).ServeHTTP(w, r)
}

// ProfileHandler handles displaying the user's profile
func (h *CookieAuthHandler) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	userId, fullname, ok := h.verifyCookie(r)
	if !ok || userId == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Render the profile template
	templ.Handler(ProfilePage(userId, fullname, true, fullname)).ServeHTTP(w, r)
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
func (h *CookieAuthHandler) setAuthCookie(w http.ResponseWriter, userId, fullname string) {
	// Create cookie value: userId|fullname|timestamp
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	cookieValue := fmt.Sprintf("%s|%s|%s", userId, fullname, timestamp)

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

// verifyCookie verifies a signed cookie and returns the userId and fullname if valid
func (h *CookieAuthHandler) verifyCookie(r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		return "", "", false
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 4 {
		return "", "", false
	}

	userId := parts[0]
	fullname := parts[1]
	timestamp := parts[2]
	signature := parts[3]

	// Verify the signature
	cookieValue := fmt.Sprintf("%s|%s|%s", userId, fullname, timestamp)
	expectedSignature := h.signCookie(cookieValue)

	if signature != expectedSignature {
		return "", "", false
	}

	// Verify cookie isn't too old (optional)
	var ts int64
	fmt.Sscanf(timestamp, "%d", &ts)
	if time.Now().Unix()-ts > maxCookieLifeTime {
		return "", "", false
	}

	return userId, fullname, true
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
		userId, _, ok := h.verifyCookie(r)
		if !ok || userId == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// User is authenticated, proceed
		next.ServeHTTP(w, r)
	})
}

// LoginHandler handles user login with cookies
func (h *CookieAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Display login form for GET requests
	if r.Method == http.MethodGet {
		// Render the login template
		templ.Handler(LoginPage("")).ServeHTTP(w, r)
		return
	}

	// Process login for POST requests
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var (
			id       string
			fullname string
			encoded  string
			error    string
		)

		// Query the database for the user
		row := h.DB.QueryRow("SELECT id, fullname, password FROM users WHERE username = ?", username)
		err := row.Scan(&id, &fullname, &encoded)

		if err != nil {
			if err == sql.ErrNoRows {
				error = "Incorrect username"
			} else {
				error = "Database error, please try again"
			}
		} else {
			// Verify the password using our auth package
			if !auth.VerifyPassword(password, encoded) {
				error = "Incorrect password"
			}
		}

		if error == "" {
			// Login successful, set auth cookie
			h.setAuthCookie(w, id, fullname)

			// Redirect to home page
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Login failed, display error
		templ.Handler(LoginPage(error)).ServeHTTP(w, r)
		return
	}

	// Method not allowed for anything else
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// RegisterHandler handles user registration
func (h *CookieAuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Display registration form for GET requests
	if r.Method == http.MethodGet {
		templ.Handler(RegisterPage("")).ServeHTTP(w, r)
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
			var existingId string
			row := h.DB.QueryRow("SELECT id FROM users WHERE username = ?", username)
			if row.Scan(&existingId) != sql.ErrNoRows {
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
		templ.Handler(RegisterPage(error)).ServeHTTP(w, r)
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
