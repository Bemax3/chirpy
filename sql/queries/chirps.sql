-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES ($1,$2,$3,$4,$5) RETURNING *;

-- name: GetChirpsByUserId :many
SELECT * FROM chirps WHERE user_id = $1;

-- name: GetChirpById :one
SELECT * FROM chirps WHERE id = $1;

-- name: DeleteChirps :exec
DELETE FROM chirps;

-- name: DeleteChirpsByUserId :exec
DELETE FROM chirps WHERE user_id = $1;

-- name: DeleteChirpById :exec
DELETE FROM chirps WHERE id = $1;

-- name: GetChirps :many
SELECT * FROM chirps ORDER BY created_at;
