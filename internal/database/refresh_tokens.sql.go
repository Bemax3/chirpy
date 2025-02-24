// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: refresh_tokens.sql

package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const createToken = `-- name: CreateToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

type CreateTokenParams struct {
	Token     string
	CreatedAt time.Time
	UpdatedAt time.Time
	UserID    uuid.UUID
	ExpiresAt time.Time
	RevokedAt sql.NullTime
}

func (q *Queries) CreateToken(ctx context.Context, arg CreateTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createToken,
		arg.Token,
		arg.CreatedAt,
		arg.UpdatedAt,
		arg.UserID,
		arg.ExpiresAt,
		arg.RevokedAt,
	)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const deleteTokens = `-- name: DeleteTokens :exec
DELETE FROM refresh_tokens
`

func (q *Queries) DeleteTokens(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteTokens)
	return err
}

const getTokenById = `-- name: GetTokenById :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at FROM refresh_tokens WHERE token = $1
`

func (q *Queries) GetTokenById(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getTokenById, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getTokenByUserId = `-- name: GetTokenByUserId :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at FROM refresh_tokens WHERE user_id = $1
`

func (q *Queries) GetTokenByUserId(ctx context.Context, userID uuid.UUID) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getTokenByUserId, userID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const revokeToken = `-- name: RevokeToken :exec
UPDATE refresh_tokens SET revoked_at = $1, updated_at = $1 WHERE token = $2
`

type RevokeTokenParams struct {
	RevokedAt sql.NullTime
	Token     string
}

func (q *Queries) RevokeToken(ctx context.Context, arg RevokeTokenParams) error {
	_, err := q.db.ExecContext(ctx, revokeToken, arg.RevokedAt, arg.Token)
	return err
}

const revokeTokenByUserId = `-- name: RevokeTokenByUserId :exec
UPDATE refresh_tokens SET revoked_at = $1, updated_at = $1 WHERE user_id = $2
`

type RevokeTokenByUserIdParams struct {
	RevokedAt sql.NullTime
	UserID    uuid.UUID
}

func (q *Queries) RevokeTokenByUserId(ctx context.Context, arg RevokeTokenByUserIdParams) error {
	_, err := q.db.ExecContext(ctx, revokeTokenByUserId, arg.RevokedAt, arg.UserID)
	return err
}
