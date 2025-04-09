package main

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
	"sort"
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
const currentFormulaESeason = "2024-25"

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

// HasSessionStarted checks if a session has already started
func HasSessionStarted(session datastore.FormulaOneSession) bool {
	if session.StartTime.Valid {
		startTime, err := time.Parse(time.RFC3339, session.StartTime.String)
		if err == nil && time.Now().After(startTime) {
			return true
		}
	}
	return false
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

	// Get session results if they exist
	var sessionResult []int64
	sessionResult, _ = app.Queries.GetSessionResultEntrantIDsForSession(ctx, sessionID)

	// Get predictions only if the session has started
	var allPredictions []FormulaOneScoredPrediction

	// Check if the session has started before fetching predictions
	hasStarted := HasSessionStarted(session)
	if hasStarted {
		// Session has started, fetch and transform predictions
		rows, err := app.Queries.GetFormulaOneScoredPredictionLines(ctx, sessionID)
		if err != nil {
			log.Error(fmt.Sprintf("Error fetching all user predictions for session %d", sessionID), err)
			// Again, handle this error scenario
			allPredictions = nil
		} else {
			// Transform into grouped predictions
			allPredictions = TransformPredictionLines(rows)
		}
	} else {
		// Session hasn't started yet, set predictions to nil
		allPredictions = nil
	}

	// Pass the session data to the SessionPage template
	templ.Handler(FormulaOneSessionPage(cookieInfo, sessionData, userPrediction, sessionResult, allPredictions)).ServeHTTP(w, r)
}

// FormulaOneScoredPrediction represents a user's complete prediction with total score
type FormulaOneScoredPrediction struct {
	UserID   int64
	UserName string
	Total    int64
	Lines    []datastore.GetFormulaOneScoredPredictionLinesRow
}

// TransformPredictionLines transforms flat query results into grouped user predictions
func TransformPredictionLines(rows []datastore.GetFormulaOneScoredPredictionLinesRow) []FormulaOneScoredPrediction {
	// Map to store predictions by user ID
	userPredictions := make(map[int64]*FormulaOneScoredPrediction)

	// Process all rows
	for _, row := range rows {
		// Check if we already have a prediction for this user
		prediction, exists := userPredictions[row.UserID]

		if !exists {
			// Create a new prediction for this user
			prediction = &FormulaOneScoredPrediction{
				UserID:   row.UserID,
				UserName: row.UserName,
				Total:    0,
				Lines:    []datastore.GetFormulaOneScoredPredictionLinesRow{},
			}
			userPredictions[row.UserID] = prediction
		}

		// Add the current row to the user's lines
		prediction.Lines = append(prediction.Lines, row)

		// Add to the total score
		prediction.Total += row.Score
	}

	// Convert map to slice for return
	result := make([]FormulaOneScoredPrediction, 0, len(userPredictions))
	for _, prediction := range userPredictions {
		result = append(result, *prediction)
	}

	// Sort by total score in descending order
	sortPredictionsByScore(result)

	// Sort each user's prediction lines by predicted position
	for i := range result {
		// We do not necessarily need to do this since they should be sorted by the SQL query
		sortPredictionLines(result[i].Lines)
	}

	return result
}

// sortPredictionsByScore sorts predictions by total score in descending order
func sortPredictionsByScore(predictions []FormulaOneScoredPrediction) {
	sort.Slice(predictions, func(i, j int) bool {
		// Sort by total score descending
		if predictions[i].Total != predictions[j].Total {
			return predictions[i].Total > predictions[j].Total
		}
		// If scores are tied, sort by username
		return predictions[i].UserName < predictions[j].UserName
	})
}

// sortPredictionLines sorts prediction lines by predicted position
func sortPredictionLines(lines []datastore.GetFormulaOneScoredPredictionLinesRow) {
	sort.Slice(lines, func(i, j int) bool {
		return lines[i].PredictedPosition < lines[j].PredictedPosition
	})
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

func (h *CookieAuthHandler) FormulaESeasonHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookieInfo := h.verifyCookie(r)

	season := chi.URLParam(r, "season")
	if season == "" {
		season = currentFormulaESeason
	}
	// Get Formula E races for the season for navigation
	events, err := app.Queries.GetFormulaERaces(ctx, season)
	if err != nil {
		log.Error("Could not retrieve events for season", err)
		// Don't return an error here, just continue with empty events
		events = []datastore.GetFormulaERacesRow{}
	}

	// Get the season leaderboard
	leaderboard, err := app.Queries.GetFormulaELeaderboard(ctx, season)
	if err != nil {
		log.Error("Could not retrieve leaderboard for season", err)
		// Don't return an error here, just continue with empty leaderboard
		leaderboard = []datastore.GetFormulaELeaderboardRow{}
	}

	templ.Handler(FormulaESeasonPage(cookieInfo, season, events, leaderboard)).ServeHTTP(w, r)
}
func (h *CookieAuthHandler) FormulaEEventHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookieInfo := h.verifyCookie(r)

	raceIdString := chi.URLParam(r, "race-id")
	raceId, err := strconv.ParseInt(raceIdString, 10, 64)
	if err != nil {
		log.Error("Invalid race ID format", err)
		http.Error(w, "Race not found", http.StatusNotFound)
		return
	}

	// Get the race information
	race, err := app.Queries.GetFormulaERace(ctx, raceId)
	if err != nil {
		log.Error("Could not retrieve the race", err)
		http.Error(w, "Race not found", http.StatusNotFound)
		return
	}

	// Get Formula E race entrants
	entrants, err := app.Queries.GetFormulaERaceEntrants(ctx, raceId)
	if err != nil {
		log.Error("Could not retrieve the entrants for the race", err)
		http.Error(w, "Could not retrieve the entrants for the race", http.StatusInternalServerError)
		return
	}

	// Check if race has started to determine if we should show predictions
	raceHasStarted := false
	raceStartTime, err := time.Parse(time.RFC3339, race.Date)
	if err == nil && time.Now().After(raceStartTime) {
		raceHasStarted = true
	}

	// Get prediction scores if race has started
	var predictionScores []datastore.GetFormulaERaceScoresRow
	if raceHasStarted {
		predictionScores, err = app.Queries.GetFormulaERaceScores(ctx, raceId)
		if err != nil {
			log.Error("Could not retrieve prediction scores", err)
			// Don't return an error, just proceed with empty scores
			predictionScores = []datastore.GetFormulaERaceScoresRow{}
		}
	}

	// Get the current user's prediction if authenticated
	var userPrediction *datastore.GetFormulaERaceUserPredictionRow
	if cookieInfo.IsAuthenticated {
		userId, err := strconv.ParseInt(cookieInfo.UserID, 10, 64)
		if err == nil {
			prediction, err := app.Queries.GetFormulaERaceUserPrediction(ctx, datastore.GetFormulaERaceUserPredictionParams{
				User:   userId,
				RaceID: raceId,
			})
			if err == nil {
				userPrediction = &prediction
			} else if err != sql.ErrNoRows {
				log.Error("Error fetching user prediction", err)
			}
		}
	}

	// Get the current race result (for admin)
	var raceResult *datastore.GetFormulaERaceResultRow
	if cookieInfo.IsAdmin {
		result, err := app.Queries.GetFormulaERaceResult(ctx, raceId)
		if err == nil {
			raceResult = &result
		} else if err != sql.ErrNoRows {
			log.Error("Error fetching race result", err)
		}
	}

	templ.Handler(FormulaERacePage(cookieInfo, race, entrants, raceHasStarted, predictionScores, userPrediction, raceResult)).ServeHTTP(w, r)
}

// FormulaEPredictionRequest represents the form data for Formula E predictions/results
type FormulaEPredictionRequest struct {
	Race      int64  `json:"race"`
	Pole      int64  `json:"pole"`
	Fam       int64  `json:"fam"`
	Fl        int64  `json:"fl"`
	Hgc       int64  `json:"hgc"`
	First     int64  `json:"first"`
	Second    int64  `json:"second"`
	Third     int64  `json:"third"`
	Fdnf      int64  `json:"fdnf"`
	SafetyCar bool   `json:"safety_car"`
	Type      string `json:"type"` // "prediction" or "result"
}

// SaveFormulaEPredictionHandler handles saving predictions or results for Formula E races
func (h *CookieAuthHandler) SaveFormulaEPredictionHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookieInfo := h.verifyCookie(r)
	if !cookieInfo.IsAuthenticated {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "You must be logged in to save predictions",
		}, http.StatusUnauthorized)
		return
	}

	// Variables to store the prediction/result data
	var raceID int64
	var predictionType string
	var pole, fam, fl, hgc, first, second, third, fdnf int64
	var safetyCar string

	// Check if content type is JSON
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		// Parse JSON request
		var req FormulaEPredictionRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Invalid JSON format",
			}, http.StatusBadRequest)
			return
		}

		raceID = req.Race
		predictionType = req.Type
		pole = req.Pole
		fam = req.Fam
		fl = req.Fl
		hgc = req.Hgc
		first = req.First
		second = req.Second
		third = req.Third
		fdnf = req.Fdnf

		// Convert boolean to string for database
		if req.SafetyCar {
			safetyCar = "yes"
		} else {
			safetyCar = "no"
		}
	} else {
		// Parse form data
		err := r.ParseForm()
		if err != nil {
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Invalid form data",
			}, http.StatusBadRequest)
			return
		}

		// Extract values from the form
		raceID, err = strconv.ParseInt(r.FormValue("race_id"), 10, 64)
		if err != nil || raceID == 0 {
			// Try alternate form field name (from JavaScript)
			raceID, err = strconv.ParseInt(r.FormValue("race"), 10, 64)
			if err != nil || raceID == 0 {
				sendJSONResponse(w, PredictionResponse{
					Success: false,
					Message: "Invalid race ID",
				}, http.StatusBadRequest)
				return
			}
		}

		// Check for both possible field names
		predictionType = r.FormValue("form_type")
		if predictionType == "" {
			predictionType = r.FormValue("type")
		}

		if r.FormValue("pole") != "" {
			pole, _ = strconv.ParseInt(r.FormValue("pole"), 10, 64)
		}
		if r.FormValue("fam") != "" {
			fam, _ = strconv.ParseInt(r.FormValue("fam"), 10, 64)
		}
		if r.FormValue("fl") != "" {
			fl, _ = strconv.ParseInt(r.FormValue("fl"), 10, 64)
		}
		if r.FormValue("hgc") != "" {
			hgc, _ = strconv.ParseInt(r.FormValue("hgc"), 10, 64)
		}
		if r.FormValue("first") != "" {
			first, _ = strconv.ParseInt(r.FormValue("first"), 10, 64)
		}
		if r.FormValue("second") != "" {
			second, _ = strconv.ParseInt(r.FormValue("second"), 10, 64)
		}
		if r.FormValue("third") != "" {
			third, _ = strconv.ParseInt(r.FormValue("third"), 10, 64)
		}
		if r.FormValue("fdnf") != "" {
			fdnf, _ = strconv.ParseInt(r.FormValue("fdnf"), 10, 64)
		}
		safetyCar = r.FormValue("safety_car")
	}

	// Validate required data
	if raceID == 0 {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Race ID is required",
		}, http.StatusBadRequest)
		return
	}

	// Get race details to check the deadline for predictions
	race, err := app.Queries.GetFormulaERace(r.Context(), raceID)
	if err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Race not found",
		}, http.StatusNotFound)
		return
	}

	// Determine whether this is a prediction or result
	if predictionType != "prediction" && predictionType != "result" {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Invalid prediction type",
		}, http.StatusBadRequest)
		return
	}

	// For result submissions, check if user is admin
	if predictionType == "result" && !cookieInfo.IsAdmin {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Admin privileges required to save results",
		}, http.StatusForbidden)
		return
	}

	// For predictions, check if race has started
	if predictionType == "prediction" {
		raceStartTime, err := time.Parse(time.RFC3339, race.Date)
		if err == nil && time.Now().After(raceStartTime) {
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Predictions cannot be submitted after the race has started",
			}, http.StatusOK) // We give an 'OK' here so the component displays the message
			return
		}
	}

	// Save to the database
	if predictionType == "prediction" {
		// Get user ID
		userID, err := strconv.ParseInt(cookieInfo.UserID, 10, 64)
		if err != nil {
			log.Error("Invalid UserID", err)
			http.Error(w, "Invalid UserID", http.StatusInternalServerError)
			return
		}

		// Insert or update prediction
		err = app.Queries.UpsertFormulaEPrediction(r.Context(), datastore.UpsertFormulaEPredictionParams{
			User:      userID,
			Race:      raceID,
			Pole:      pole,
			Fam:       fam,
			Fl:        fl,
			Hgc:       hgc,
			First:     first,
			Second:    second,
			Third:     third,
			Fdnf:      fdnf,
			SafetyCar: safetyCar,
		})
		if err != nil {
			log.Error("Could not save prediction", err)
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Failed to save prediction",
			}, http.StatusInternalServerError)
			return
		}

		sendJSONResponse(w, PredictionResponse{
			Success: true,
			Message: "Prediction saved successfully",
		}, http.StatusOK)
	} else {
		// This is a result submission
		err = app.Queries.UpsertFormulaEResult(r.Context(), datastore.UpsertFormulaEResultParams{
			Race:      raceID,
			Pole:      pole,
			Fam:       fam,
			Fl:        fl,
			Hgc:       hgc,
			First:     first,
			Second:    second,
			Third:     third,
			Fdnf:      fdnf,
			SafetyCar: safetyCar,
		})
		if err != nil {
			log.Error("Could not save result", err)
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Failed to save result",
			}, http.StatusInternalServerError)
			return
		}

		sendJSONResponse(w, PredictionResponse{
			Success: true,
			Message: "Result saved successfully",
		}, http.StatusOK)
	}
}
