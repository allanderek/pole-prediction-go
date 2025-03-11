-- name: GetDrivers :many
select * from drivers
;

-- name: GetUser :one
select id, fullname, password from users where username = ?
;

-- name: UserExists :one
select exists(select 1 from users where username = ?) 
;

-- name: AddNewUser :exec
insert into users (
    fullname, username, password
    ) values
    (@fullname, @username, @password)
;


-- name: GetFormulaOneEvents :many
select * from formula_one_events_view
where season = @season
;

-- name: GetFormulaOneEvent :one
select * from formula_one_events_view
where id = @event_id
;

-- name: GetFormulaOneSessionsByEvent :many
select 
    s.id, 
    s.name, 
    s.half_points, 
    s.start_time, 
    s.cancelled, 
    s.event, 
    s.fastest_lap
from formula_one_sessions s
where s.event = @event_id
order BY s.start_time
;

-- name: GetFormulaOneEntrantsBySession :many
select 
    e.id,
    e.number,
    e.driver,
    e.team,
    e.session,
    coalesce(e.participating, 0) as participating,
    e.rank,
    d.name as driver_name,
    t.fullname as team_fullname,
    t.shortname as team_shortname,
    coalesce(t.color, '#000000') as team_color,
    coalesce(t.secondary_color, '#000000') as team_secondary_color
from formula_one_entrants e
join drivers d on e.driver = d.id
join formula_one_teams t on e.team = t.id
where e.session = @session_id
order by e.rank desc, e.number
;


-- name: GetFormulaOneSessionByID :one
select *
from formula_one_sessions
where id = @session_id
;

-- name: GetUserPredictionForSession :many
select
    p.position,
    p.entrant
from formula_one_prediction_lines p
where p.user = @user_id
and p.session = @session_id
order by p.position;

-- name: DeleteFormulaOnePredictionLines :exec
delete from formula_one_prediction_lines
where user = @user_id
and session = @session_id;

-- name: CreateFormulaOnePredictionLine :exec
insert into formula_one_prediction_lines (
    user,
    session,
    position,
    entrant
) values (
    @user_id,
    @session_id,
    @position,
    @entrant_id
);

-- name: GetUserPredictionEntrantIDsForSession :many
select
    p.entrant
from formula_one_prediction_lines p
where p.user = @user_id
and p.session = @session_id
order by p.position
;

-- name: CreateFormulaOneSeasonPredictionLine :exec
insert into formula_one_season_prediction_lines (
    user,
    season,
    position,
    team
) values (
    @user_id,
    @season,
    @position,
    @team_id
);

-- name: DeleteFormulaOneSeasonPredictionLines :exec
delete from formula_one_season_prediction_lines
where user = @user_id
and season = @season;

-- name: GetFormulaOneSeasonPrediction :many
select
    p.position,
    p.team,
    t.fullname as team_fullname,
    t.shortname as team_shortname,
    t.color as team_color,
    t.secondary_color as team_secondary_color
from formula_one_season_prediction_lines p
join formula_one_teams t on p.team = t.id
where p.user = @user_id
and p.season = @season
order by p.position
;

-- name: GetTeamsByFormulaOneSeason :many
select
    t.id,
    t.fullname,
    t.shortname,
    coalesce(t.color, '#000000') as color,
    coalesce(t.secondary_color, '#000000') as secondary_color,
    c.name as constructor_name
from formula_one_teams t
join constructors c on t.constructor = c.id
where t.season = @season
order by t.fullname
;
