-- name: GetDrivers :many
select * from drivers
;

-- name: GetUser :one
select id, admin, fullname, password from users where username = ?
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


-- name: CreateFormulaOneResultLine :exec
insert into formula_one_prediction_lines (user, session, position, entrant, fastest_lap) 
values ("", @session_id, @position, @entrant_id, @fastest_lap)
on conflict(user,session,position) 
do update
set entrant=excluded.entrant, fastest_lap=excluded.fastest_lap
;

-- name: GetSessionResultEntrantIDsForSession :many
select r.entrant
from formula_one_prediction_lines r
where r.session = @session_id and user = ""
order by r.position
;


-- name: GetFormulaOneScoredPredictionLines :many
WITH 
    user_predictions AS (
        SELECT 
            user,
            session,
            entrant,
            position,
            fastest_lap
        FROM formula_one_prediction_lines
        WHERE user IS NOT NULL and user != ""
        AND formula_one_prediction_lines.session = @session_id
    ),
    session_results AS (
        SELECT 
            entrant,
            position,
            fastest_lap
        FROM formula_one_prediction_lines
        WHERE user IS NULL or user = ""
        AND session = @session_id
    )
SELECT 
    up.user AS user_id,
    u.fullname AS user_name,
    up.position AS predicted_position,
    sr.position AS actual_position,
    d.name AS driver_name,
    CASE 
        WHEN up.position <= 10 AND sr.position <= 10 THEN
            CASE 
                WHEN up.position = sr.position THEN 4
                WHEN ABS(up.position - sr.position) = 1 THEN 2
                ELSE 1
            END
        ELSE 0
    END + 
    CASE 
        WHEN s.fastest_lap = 1 
        AND up.fastest_lap = 1
        AND sr.fastest_lap = 1
        AND sr.position <= 10 THEN 1
        ELSE 0
    END AS score
FROM user_predictions up
JOIN users u ON up.user = u.id
JOIN session_results sr ON up.entrant = sr.entrant
JOIN formula_one_entrants fe ON up.entrant = fe.id
JOIN drivers d ON fe.driver = d.id
JOIN formula_one_sessions s ON up.session = s.id
ORDER BY u.fullname, up.position
;


-- name: GetFormulaOneSeasonLeaderboard :many
with
    results as (select * from formula_one_prediction_lines where user == ""),
    scored_lines as (
    select 
        sessions.name as session_name,
        case 
            when sessions.name = "race" then
                case 
                    when results.position = 1 then 25
                    when results.position = 2 then 18
                    when results.position = 3 then 15
                    when results.position = 4 then 12
                    when results.position = 5 then 10
                    when results.position = 6 then 8
                    when results.position = 7 then 6
                    when results.position = 8 then 4
                    when results.position = 9 then 2
                    when results.position = 10 then 1
                else 0
                end 
            when sessions.name = "sprint" then
                case 
                    when results.position = 1 then 8
                    when results.position = 2 then 7
                    when results.position = 3 then 6
                    when results.position = 4 then 5
                    when results.position = 5 then 4
                    when results.position = 6 then 3
                    when results.position = 7 then 2
                    when results.position = 8 then 1
                else 0
                end 
        end
        +
        case when results.fastest_lap = "true" and sessions.fastest_lap == true then 1 else 0 end
            as score,
        teams.shortname as team_name,
        teams.id as team_id
        from results
        inner join formula_one_sessions as sessions on results.session = sessions.id
        inner join formula_one_events as events on sessions.event == events.id and events.season == ?
        inner join formula_one_entrants as entrants on results.entrant == entrants.id
        inner join formula_one_teams as teams on entrants.team == teams.id
    ),
    constructors as (
    select 
        row_number() over (order by sum(score) desc) as position,
        team_name,
        team_id,
        sum (score) as total
        from scored_lines
        group by team_id
        order by total desc
    ),
    predictions as (
    select
        lines.team as team_id,
        COALESCE(constructors.total, 0) as total,  -- Use 0 if no results yet
        lines.position as position,
        lines.user as user
        from formula_one_season_prediction_lines as lines
        left join constructors on lines.team = constructors.team_id
    )
select
    users.id as user,
    users.fullname as fullname,
    predictions.position as position,
    teams.shortname as team,
    coalesce(teams.color, '#000000') as team_color,
    coalesce(teams.secondary_color, '#000000') as team_secondary_color,
    cast(coalesce(max(0, constructors.total - predictions.total), 0) as integer) as difference
    from predictions
    left join constructors on predictions.position = constructors.position
    inner join formula_one_teams as teams on predictions.team_id = teams.id
    inner join users on predictions.user = users.id
    order by predictions.position asc
    ;
