package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/allanderek/pole-prediction-go/datastore"
	"github.com/allanderek/pole-prediction-go/log"
	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"net/http"
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
			}, http.StatusBadRequest)
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

// SeasonPredictionRequest represents the JSON payload from the client for season predictions
type SeasonPredictionRequest struct {
	Season    string  `json:"season"`
	TeamOrder []int64 `json:"team_order"`
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
	
	// Pass the data to the template
	templ.Handler(FormulaOneSeasonPage(cookieInfo, season, teams, userPrediction, events)).ServeHTTP(w, r)
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

	// Check we have the right number of teams (for constructor standings, usually top 10)
	if len(req.TeamOrder) > 10 {
		sendJSONResponse(w, PredictionResponse{
			Success: false,
			Message: "Prediction should include at most 10 teams",
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
