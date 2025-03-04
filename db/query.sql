-- name: GetDrivers :many
select * from drivers
;

-- name: GetUser :one
select id, fullname, password from users where username = ?
;

-- name: UserExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE username = ?) 
;
