# Pole-Prediction Game Specification

## Overview

This specification outlines a web application for managing Formula 1 and Formula E prediction games. Users can make predictions about race outcomes, view their own and others' predictions, and track results on leaderboards.

## Technical Stack

- **Backend**: Go
- **HTML Templating**: templ
- **Database**: SQLite with SQLC for DB connectivity
- **Authentication**: Session-based authentication using the users table

## User Types

1. **Standard Users**: Can log in, make and view predictions, and view results and leaderboards
2. **Admin Users**: Have all standard user capabilities plus the ability to enter official results

## Core Features

### Authentication

- User registration with username, full name, and password
- Login functionality with session management
- Logout functionality
- Password should be securely hashed in the database

### User Dashboard

- Overview of upcoming sessions/races for both Formula 1 and Formula E
- Quick links to make predictions for upcoming events
- Summary of recent results and user's performance

### Formula 1 Prediction System

- Users can predict the finishing order (positions 1-10) for:
  - Qualifying sessions
  - Sprint shootout sessions
  - Sprint races
  - Main races
- For race sessions, users can also predict which driver will set the fastest lap
- Predictions should be locked once a session starts
- UI should clearly show which sessions are open for predictions

### Formula E Prediction System

- For each race, users predict:
  - Pole position (pole)
  - Fastest lap (fl)
  - Fan boost winner (fam)
  - Highest grid climber (hgc)
  - Podium positions (first, second, third)
  - First driver not to finish (fdnf)
  - Safety car appearance (yes/no)
- Predictions should be locked once a race starts

### Results View

- After a session starts, all users' predictions should be viewable by everyone
- Results should be prominently displayed once entered by an admin
- Highlight correct predictions to make it easy to see who predicted correctly

### Leaderboards

- **Formula 1 Leaderboard**:
  - Points awarded based on accuracy of position predictions
  - Separate scoring for each session type
  - Season-long leaderboard tracking total points
  
- **Formula E Leaderboard**:
  - Points awarded for each correctly predicted element
  - Season-long leaderboard tracking total points

### Admin Features

- Interface for entering official results for both Formula 1 and Formula E events
- Ability to mark races/sessions as cancelled
- Management of drivers, teams, and other reference data
- User management (e.g., granting admin privileges)

## Data Structures

The application will use the existing database schema, with key tables including:

### Common Tables
- `users`: Authentication and user information
- `drivers`: Driver information shared across both series
- `seasons`: Season information

### Formula E Tables
- `formula_e_constructors`: Constructor information
- `teams`: Team entries per season
- `races`: Race events
- `entrants`: Driver/team entries per race
- `predictions`: User predictions
- `results`: Official race results

### Formula 1 Tables
- `constructors`: F1 constructor information
- `formula_one_seasons`: Season information
- `formula_one_teams`: Team entries per season
- `formula_one_events`: Race weekends
- `formula_one_sessions`: Individual sessions within events
- `formula_one_entrants`: Driver/team entries per session
- `formula_one_prediction_lines`: User predictions per position
- `formula_one_season_prediction_lines`: Season-long constructor predictions

## User Interface Flow

### Login/Registration Flow
1. Home page with login form
2. New user registration option
3. Redirect to dashboard upon successful login

### Dashboard Flow
1. Overview of upcoming sessions for both series
2. Quick links to make predictions
3. Navigation to detailed views

### Prediction Flow (Formula 1)
1. Select an upcoming session
2. View list of participating drivers
3. Arrange drivers in predicted finishing order
4. Submit predictions

### Prediction Flow (Formula E)
1. Select an upcoming race
2. View list of participating drivers
3. Select drivers for each prediction category
4. Submit predictions

### Results and Leaderboard Flow
1. View all users' predictions once session starts
2. View results and points awarded
3. Filter leaderboards by season or event

## Scoring System

### Formula 1 Scoring
- Points awarded based on how close each predicted position is to the actual result
- Bonus points for correctly predicting the exact position
- Bonus points for correctly predicting fastest lap (where applicable)

### Formula E Scoring
- Points for each correctly predicted category
- Weighted scoring based on difficulty of prediction (e.g., more points for correct pole prediction than safety car prediction)

## Technical Considerations

### Security
- Secure password storage
- Session management
- Input validation and sanitization

### Performance
- Efficient database queries using SQLC
- Optimized templates for quick page loading

### Usability
- Mobile-responsive design
- Clear indicators for prediction deadlines
- Intuitive drag-and-drop interface for ordering predictions

## Implementation Phases

### Phase 1: Authentication and Basic Structure
- User authentication
- Basic dashboard
- Navigation structure

### Phase 2: Formula 1 Prediction System
- Session listing
- Prediction interface
- Results viewing

### Phase 3: Formula E Prediction System
- Race listing
- Prediction interface
- Results viewing

### Phase 4: Leaderboards and Admin Features
- Leaderboard calculations
- Admin result entry
- User management

### Phase 5: Refinement and Additional Features
- UI/UX improvements
- Performance optimization
- Additional statistics and visualizations

Would you like me to elaborate on any specific section of this specification?
