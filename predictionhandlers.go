package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/a-h/templ"
	"github.com/allanderek/pole-prediction-go/datastore"
	"github.com/allanderek/pole-prediction-go/log"
	"github.com/go-chi/chi/v5"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// PredictionRequest represents the JSON payload from the client
type PredictionRequest struct {
	SessionID    int64   `json:"session_id"`
	EntrantOrder []int64 `json:"entrant_order"`
}

// PredictionResponse is sent back to the client
type PredictionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// SaveFormulaOnePrediction handles saving a user's prediction for a session
func (h *CookieAuthHandler) SaveFormulaOnePrediction(w http.ResponseWriter, r *http.Request) {
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

	// Parse JSON request
	var req PredictionRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Invalid request format",
		}, http.StatusBadRequest)
		return
	}

	// Validate the request has required fields
	if req.SessionID == 0 || len(req.EntrantOrder) == 0 {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Missing required fields",
		}, http.StatusBadRequest)
		return
	}

	// Get session details to check the deadline
	session, err := app.Queries.GetFormulaOneSessionByID(r.Context(), req.SessionID)
	if err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Session not found",
		}, http.StatusNotFound)
		return
	}

	// Check if the session has started
	if session.StartTime.Valid {
		startTime, err := time.Parse(time.RFC3339, session.StartTime.String)
		if err == nil && time.Now().After(startTime) {
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Predictions cannot be submitted after the session has started",
			}, http.StatusOK) // We give an 'OK' here otherwise the component does not display the message.
			return
		}
	}

	// Validate all entrant IDs belong to this session
	err = validateEntrants(r.Context(), req.SessionID, req.EntrantOrder)
	if err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: err.Error(),
		}, http.StatusBadRequest)
		return
	}
	userID, err := strconv.ParseInt(cookieInfo.UserID, 10, 64)
	if err != nil {
		log.Error("Invalid UserID", err)
		http.Error(w, "Invalid UserID", http.StatusInternalServerError)
		return
	}

	// Begin a transaction
	tx, err := app.DB.Begin()
	if err != nil {
		log.Error("Could not begin a transaction", err)
		http.Error(w, "Could not begin a transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Delete any existing predictions for this user and session
	err = app.Queries.DeleteFormulaOnePredictionLines(r.Context(), datastore.DeleteFormulaOnePredictionLinesParams{
		UserID:    userID,
		SessionID: req.SessionID,
	})
	if err != nil {
		log.Error("Could not delete former prediction lines", err)
		http.Error(w, "Could not delete former prediction lines", http.StatusInternalServerError)
		return
	}

	// Insert new prediction lines
	for position, entrantID := range req.EntrantOrder {
		// Positions are 1-based in the database
		positionNum := int64(position + 1)

		// Insert prediction line
		err = app.Queries.CreateFormulaOnePredictionLine(r.Context(), datastore.CreateFormulaOnePredictionLineParams{
			UserID:    userID,
			SessionID: req.SessionID,
			Position:  positionNum,
			EntrantID: entrantID,
		})

		if err != nil {
			log.Error("Could not insert prediction lines", err)
			http.Error(w, "Could not insert prediction lines", http.StatusInternalServerError)
			return
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		log.Error("Could not commit the db transaction", err)
		http.Error(w, "Could not commit the db transaction", http.StatusInternalServerError)
		return
	}

	// Send success response
	sendJSONResponse(w, PredictionResponse{
		Success: true,
		Message: "Prediction saved successfully",
	}, http.StatusOK)
}

// Helper function to validate all entrant IDs
func validateEntrants(ctx context.Context, sessionID int64, entrantIDs []int64) error {
	// Get all entrants for this session
	entrants, err := app.Queries.GetFormulaOneEntrantsBySession(ctx, sessionID)
	if err != nil {
		return errors.New("unable to validate entrants")
	}

	// Create a map of valid entrant IDs for quick lookup
	validEntrants := make(map[int64]bool)
	for _, e := range entrants {
		validEntrants[e.ID] = true
	}

	// Check each provided entrant ID
	for _, id := range entrantIDs {
		if !validEntrants[id] {
			return errors.New("invalid entrant ID in prediction")
		}
	}

	// Check we have the right number of entrants
	if len(entrantIDs) != len(entrants) {
		return errors.New("prediction must include all entrants")
	}

	// Check for duplicate entrant IDs
	seen := make(map[int64]bool)
	for _, id := range entrantIDs {
		if seen[id] {
			return errors.New("duplicate entrant ID in prediction")
		}
		seen[id] = true
	}

	return nil
}

// Helper function to send JSON responses
func sendJSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// ResultRequest represents the JSON payload from the admin for session results
type ResultRequest struct {
	SessionID    int64   `json:"session_id"`
	EntrantOrder []int64 `json:"entrant_order"`
}

// SaveFormulaOneResult handles saving admin-entered results for a session
func (h *CookieAuthHandler) SaveFormulaOneResult(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify admin privileges
	cookieInfo := h.verifyCookie(r)
	if !cookieInfo.IsAuthenticated {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "You must be logged in to save results",
		}, http.StatusUnauthorized)
		return
	}

	if !cookieInfo.IsAdmin {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Admin privileges required to save results",
		}, http.StatusForbidden)
		return
	}

	// Parse JSON request
	var req ResultRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Invalid request format",
		}, http.StatusBadRequest)
		return
	}

	// Validate the request has required fields
	if req.SessionID == 0 || len(req.EntrantOrder) == 0 {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Missing required fields",
		}, http.StatusBadRequest)
		return
	}

	// Validate all entrant IDs belong to this session
	err := validateEntrants(r.Context(), req.SessionID, req.EntrantOrder)
	if err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: err.Error(),
		}, http.StatusBadRequest)
		return
	}

	// Begin a transaction
	tx, err := app.DB.Begin()
	if err != nil {
		log.Error("Could not begin a transaction", err)
		http.Error(w, "Could not begin a transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Insert new result lines
	// Note we do not need to delete any exising result lines, as the query to create them does an upsert
	for position, entrantID := range req.EntrantOrder {
		// Positions are 1-based in the database
		positionNum := int64(position + 1)

		// Insert result line
		err = app.Queries.CreateFormulaOneResultLine(r.Context(), datastore.CreateFormulaOneResultLineParams{
			SessionID: req.SessionID,
			Position:  positionNum,
			EntrantID: entrantID,
		})

		if err != nil {
			log.Error("Could not insert result lines", err)
			http.Error(w, "Could not insert result lines", http.StatusInternalServerError)
			return
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		log.Error("Could not commit the db transaction", err)
		http.Error(w, "Could not commit the db transaction", http.StatusInternalServerError)
		return
	}

	// Send success response
	sendJSONResponse(w, PredictionResponse{
		Success: true,
		Message: "Result saved successfully",
	}, http.StatusOK)
}

// SeasonPredictionRequest represents the JSON payload from the client for season predictions
type SeasonPredictionRequest struct {
	Season    string  `json:"season"`
	TeamOrder []int64 `json:"team_order"`
}

// FormulaOneScoredSeasonPrediction represents a user's complete season prediction with total score
type FormulaOneScoredSeasonPrediction struct {
	UserID   int64
	UserName string
	Total    int64
	Lines    []datastore.GetFormulaOneSeasonLeaderboardRow
}

// FormulaOneSeasonHandler displays the Formula One season page with constructor standings prediction
func (h *CookieAuthHandler) FormulaOneSeasonHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cookieInfo := h.verifyCookie(r)

	// Get season from URL
	season := chi.URLParam(r, "season")
	if season == "" {
		season = currentSeason // Default to current season (defined in handlers.go)
	}

	// Get teams for this season
	teams, err := app.Queries.GetTeamsByFormulaOneSeason(ctx, season)
	if err != nil {
		log.Error("Could not retrieve teams for season", err)
		http.Error(w, "Unable to retrieve teams", http.StatusInternalServerError)
		return
	}

	// If user is authenticated, get their existing season prediction
	var userPrediction []datastore.GetFormulaOneSeasonPredictionRow
	if cookieInfo.IsAuthenticated {
		userID, err := strconv.ParseInt(cookieInfo.UserID, 10, 64)
		if err == nil {
			userPrediction, err = app.Queries.GetFormulaOneSeasonPrediction(ctx, datastore.GetFormulaOneSeasonPredictionParams{
				UserID: userID,
				Season: season,
			})
			if err != nil {
				log.Error("Could not retrieve user's season prediction", err)
				// Don't return an error here, just continue with empty prediction
				userPrediction = []datastore.GetFormulaOneSeasonPredictionRow{}
			}
		}
	}

	// Get Formula One events for the season for navigation
	events, err := app.Queries.GetFormulaOneEvents(ctx, season)
	if err != nil {
		log.Error("Could not retrieve events for season", err)
		// Don't return an error here, just continue with empty events
		events = []datastore.FormulaOneEventsView{}
	}

	// Get predictions only if the session has started
	var allPredictions []FormulaOneScoredSeasonPrediction
	var leaderboard []datastore.GetFormulaOneLeaderboardRow

	// Check if the session has started before fetching predictions
	hasStarted := SeasonHasStarted()
	if hasStarted {
		// If the season has started, fetch and transform predictions
		rows, err := app.Queries.GetFormulaOneSeasonLeaderboard(ctx, season)
		if err != nil {
			log.Error("Error fetching all user predictions for the season", err)
			allPredictions = nil
		} else {
			// Transform into grouped predictions
			allPredictions = TransformSeasonPredictionLines(rows)
		}

		leaderboard, err = app.Queries.GetFormulaOneLeaderboard(ctx, season)
		if err != nil {
			log.Error("Error fetching leaderboard for the season", err)
			leaderboard = nil
		}

	} else {
		// Session hasn't started yet, set predictions to nil
		allPredictions = nil
		leaderboard = nil
	}

	// Pass the data to the template
	templ.Handler(FormulaOneSeasonPage(cookieInfo, season, teams, userPrediction, events, allPredictions, leaderboard)).ServeHTTP(w, r)
}

// TransformSeasonPredictionLines transforms flat query results into grouped user predictions
func TransformSeasonPredictionLines(rows []datastore.GetFormulaOneSeasonLeaderboardRow) []FormulaOneScoredSeasonPrediction {
	// Map to store predictions by user ID
	userPredictions := make(map[int64]*FormulaOneScoredSeasonPrediction)

	// Process all rows
	for _, row := range rows {
		// Check if we already have a prediction for this user
		prediction, exists := userPredictions[row.User]

		if !exists {
			// Create a new prediction for this user
			prediction = &FormulaOneScoredSeasonPrediction{
				UserID:   row.User,
				UserName: row.Fullname,
				Total:    0,
				Lines:    []datastore.GetFormulaOneSeasonLeaderboardRow{},
			}
			userPredictions[row.User] = prediction
		}

		// Add to the total difference (lower is better)
		prediction.Total += row.Difference

		// Add the current line to the user's lines
		prediction.Lines = append(prediction.Lines, row)
	}

	// Convert map to slice for return
	result := make([]FormulaOneScoredSeasonPrediction, 0, len(userPredictions))
	for _, prediction := range userPredictions {
		result = append(result, *prediction)
	}

	// Sort by total difference in ascending order (lower is better)
	sortSeasonPredictionsByScore(result)

	// Sort each user's prediction lines by position
	// Again we do not really need to do this since they should be in sorted order anyway from the database
	for i := range result {
		sortSeasonPredictionLinesByPosition(result[i].Lines)
	}

	return result
}

// sortSeasonPredictionsByScore sorts predictions by total difference in ascending order
func sortSeasonPredictionsByScore(predictions []FormulaOneScoredSeasonPrediction) {
	sort.Slice(predictions, func(i, j int) bool {
		// Sort by total difference ascending (lower is better)
		if predictions[i].Total != predictions[j].Total {
			return predictions[i].Total < predictions[j].Total
		}
		// If totals are tied, sort by username
		return predictions[i].UserName < predictions[j].UserName
	})
}

// sortSeasonPredictionLinesByPosition sorts prediction lines by position
func sortSeasonPredictionLinesByPosition(lines []datastore.GetFormulaOneSeasonLeaderboardRow) {
	sort.Slice(lines, func(i, j int) bool {
		return lines[i].Position < lines[j].Position
	})
}

// FormulaOneSeasonStart is the start time for the Formula One season
var FormulaOneSeasonStart string = "2025-03-14T01:30:00Z"

func SeasonHasStarted() bool {
	startTime, err := time.Parse(time.RFC3339, FormulaOneSeasonStart)
	return err == nil && time.Now().After(startTime)
}

// SaveFormulaOneSeasonPrediction handles saving a user's prediction for a season's constructor standings
func (h *CookieAuthHandler) SaveFormulaOneSeasonPrediction(w http.ResponseWriter, r *http.Request) {
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

	if SeasonHasStarted() {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Season predictions cannot be submitted after the first practice session of the season has started",
		}, http.StatusOK)
		return
	}

	// Parse JSON request
	var req SeasonPredictionRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Invalid request format",
		}, http.StatusBadRequest)
		return
	}

	// Validate the request has required fields
	if req.Season == "" || len(req.TeamOrder) == 0 {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Missing required fields",
		}, http.StatusBadRequest)
		return
	}

	// Validate all team IDs belong to this season
	teams, err := app.Queries.GetTeamsByFormulaOneSeason(r.Context(), req.Season)
	if err != nil {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Season not found",
		}, http.StatusNotFound)
		return
	}

	// Create a map of valid team IDs for quick lookup
	validTeams := make(map[int64]bool)
	for _, t := range teams {
		validTeams[t.ID] = true
	}

	// Check each provided team ID
	for _, id := range req.TeamOrder {
		if !validTeams[id] {
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Invalid team ID in prediction",
			}, http.StatusBadRequest)
			return
		}
	}

	numValidTeams := len(teams)

	// Check we have the right number of teams (for constructor standings, usually top 10)
	if len(req.TeamOrder) > numValidTeams {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: fmt.Sprintf("Prediction should include at most %d teams", numValidTeams),
		}, http.StatusBadRequest)
		return
	}

	// Check for duplicate team IDs
	seen := make(map[int64]bool)
	for _, id := range req.TeamOrder {
		if seen[id] {
			sendJSONResponse(w, PredictionResponse{
				Success: false,
				Message: "Duplicate team ID in prediction",
			}, http.StatusBadRequest)
			return
		}
		seen[id] = true
	}

	userID, err := strconv.ParseInt(cookieInfo.UserID, 10, 64)
	if err != nil {
		log.Error("Invalid UserID", err)
		http.Error(w, "Invalid UserID", http.StatusInternalServerError)
		return
	}

	// Begin a transaction
	tx, err := app.DB.Begin()
	if err != nil {
		log.Error("Could not begin a transaction", err)
		http.Error(w, "Could not begin a transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Delete any existing predictions for this user and season
	err = app.Queries.DeleteFormulaOneSeasonPredictionLines(r.Context(), datastore.DeleteFormulaOneSeasonPredictionLinesParams{
		UserID: userID,
		Season: req.Season,
	})
	if err != nil {
		log.Error("Could not delete former season prediction lines", err)
		http.Error(w, "Could not delete former season prediction lines", http.StatusInternalServerError)
		return
	}

	// Insert new prediction lines
	for position, teamID := range req.TeamOrder {
		// Positions are 1-based in the database
		positionNum := int64(position + 1)

		// Insert prediction line
		err = app.Queries.CreateFormulaOneSeasonPredictionLine(r.Context(), datastore.CreateFormulaOneSeasonPredictionLineParams{
			UserID:   userID,
			Season:   req.Season,
			Position: positionNum,
			TeamID:   teamID,
		})

		if err != nil {
			log.Error("Could not insert season prediction lines", err)
			http.Error(w, "Could not insert season prediction lines", http.StatusInternalServerError)
			return
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		log.Error("Could not commit the db transaction", err)
		http.Error(w, "Could not commit the db transaction", http.StatusInternalServerError)
		return
	}

	// Send success response
	sendJSONResponse(w, PredictionResponse{
		Success: true,
		Message: "Season prediction saved successfully",
	}, http.StatusOK)
}
