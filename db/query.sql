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
select 
    id, round, name, season,
    case
    when exists (
        select 1
        from formula_one_sessions
        where event = events.id and name = "sprint"
    ) then 1
    else 0 
    end as isSprint,
    -- This cast helps sqlc generate the correct output type.
    cast(( select min(start_time) from formula_one_sessions where event = events.id) as text) as start_time
from formula_one_events as events
where season = @season
;
