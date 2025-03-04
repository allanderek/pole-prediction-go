-- name: GetDrivers :many
select * from drivers
;

-- name: GetUser :one
select id, fullname, password from users where username = ?
;
