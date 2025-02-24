package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Bemax3/chirpy/internal/auth"
	"github.com/Bemax3/chirpy/internal/database"
	"github.com/Bemax3/chirpy/internal/types"
	"github.com/google/uuid"
)

type ApiConfig struct {
	Db             *database.Queries
	FileserverHits atomic.Int32
	JwtSecret      string
	PolkaKey       string
}

type errorResponse struct {
	Error string `json:"error"`
}

type H map[string]any

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)

	result, _ := json.Marshal(errorResponse{
		Error: msg,
	})

	w.Write(result)
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	w.WriteHeader(code)

	result, _ := json.Marshal(payload)

	w.Write(result)
}

func (cfg *ApiConfig) MiddlewareMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.FileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func (cfg *ApiConfig) MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf(
		`<html>
		  <body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		  </body>
		</html>`,
		cfg.FileserverHits.Load())))
}

func (cfg *ApiConfig) ResetHandler(w http.ResponseWriter, req *http.Request) {
	cfg.FileserverHits.Store(0)
	env := os.Getenv("PLATFORM")
	if env != "dev" {
		respondWithError(w, 403, "Action Forbidden")
		return
	}
	cfg.Db.DeleteUsers(req.Context())
	cfg.Db.DeleteChirps(req.Context())
	cfg.Db.DeleteTokens(req.Context())
}

func HealthzHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (cfg *ApiConfig) LoginHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		respondWithError(w, 500, "Error decoding parameters")
		return
	}

	user, err := cfg.Db.GetUserByEmail(req.Context(), params.Email)

	if err != nil {
		respondWithError(w, 404, "Error finding user with the given email address")
		return
	}

	if err := auth.CheckPasswordHash(user.HashedPassword, params.Password); err != nil {
		respondWithError(w, 401, "Invalid credentials")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.JwtSecret, time.Hour*1)

	if err != nil {
		respondWithError(w, 500, "An error occured try again later")
		return
	}

	refresh, err := GetOrCreateRefreshToken(cfg, req, user.ID)

	if err != nil {
		respondWithError(w, 500, "An error occured try again later")
		return
	}

	respondWithJson(w, 200, types.LoggedInUser{
		User: types.User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
			Email:       user.Email,
			IsChirpyRed: user.IsChirpyRed,
		},
		Token:   token,
		Refresh: refresh.Token,
	})
	return
}

func (cfg *ApiConfig) CreateUserHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		respondWithError(w, 500, "Error decoding parameters")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		log.Printf("Error while hashing password: %v", err)
		respondWithError(w, 500, "Error while hashing password")
		return
	}

	user, err := cfg.Db.CreateUser(req.Context(), database.CreateUserParams{
		ID:             uuid.New(),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})

	if err != nil {
		log.Printf("Error while creating user: %v", err)
		respondWithError(w, 500, "Error while creating user")
		return
	}

	respondWithJson(w, 201, types.User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
	return
}

func (cfg *ApiConfig) UpdateUserHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		respondWithError(w, 500, "Error decoding parameters")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		log.Printf("Error while hashing password: %v", err)
		respondWithError(w, 500, "Error while hashing password")
		return
	}

	token, err := auth.GetBearerToken(req.Header)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.JwtSecret)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	user, err := cfg.Db.UpdateUser(req.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          params.Email,
		HashedPassword: hashedPassword,
		UpdatedAt:      time.Now(),
	})

	if err != nil {
		log.Printf("Error while updating user: %v", err)
		respondWithError(w, 500, "Error while creating user")
		return
	}

	respondWithJson(w, 200, types.User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	})
	return
}

func (cfg *ApiConfig) CreateChirpHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}

	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		respondWithError(w, 500, "Error decoding parameters")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	cleaned := cleanInput(params.Body)
	token, err := auth.GetBearerToken(req.Header)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.JwtSecret)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	chirp, err := cfg.Db.CreateChirp(req.Context(), database.CreateChirpParams{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Body:      cleaned,
		UserID:    userID,
	})

	if err != nil {
		log.Printf("Error while creating chirp: %v", err)
		respondWithError(w, 500, "Error while creating chirp")
		return
	}

	respondWithJson(w, 201, types.Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	})
	return
}

func (cfg *ApiConfig) DeleteChirpHandler(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.JwtSecret)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	chirpId, err := uuid.Parse(req.PathValue("chirpID"))

	if err != nil {
		respondWithError(w, 422, "Invalid uuid given")
		return
	}

	chirp, err := cfg.Db.GetChirpById(req.Context(), chirpId)

	if err != nil {
		respondWithError(w, 404, "Error while getting chirp")
		return
	}

	if chirp.UserID != userID {
		respondWithError(w, 403, "Unauthorized Action")
		return
	}

	err = cfg.Db.DeleteChirpById(req.Context(), chirp.ID)

	if err != nil {
		respondWithError(w, 403, "Error deleting chirp")
		return
	}

	respondWithJson(w, 204, nil)
	return
}

func (cfg *ApiConfig) GetChirpsHandler(w http.ResponseWriter, req *http.Request) {
	s := req.URL.Query().Get("author_id")
	sortOrder := req.URL.Query().Get("sort")
	if sortOrder == "" || sortOrder != "desc" {
		sortOrder = "asc"
	}

	var chirps []database.Chirp
	var err error
	if s == "" {
		chirps, err = cfg.Db.GetChirps(req.Context())

		if err != nil {
			respondWithError(w, 500, "Error while getting chirps")
			return
		}

	} else {
		parsedUserId, err := uuid.Parse(s)
		if err != nil {
			respondWithError(w, 500, "Invalid User Id")
			return
		}

		chirps, err = cfg.Db.GetChirpsByUserId(req.Context(), parsedUserId)

		if err != nil {
			respondWithError(w, 500, "Error while getting chirps")
			return
		}
	}

	var result []types.Chirp

	for _, chirp := range chirps {
		result = append(result, types.Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserId:    chirp.UserID,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if sortOrder == "asc" {
			return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
		}
		return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
	})

	respondWithJson(w, 200, result)
	return
}

func (cfg *ApiConfig) GetChirpHandler(w http.ResponseWriter, req *http.Request) {

	chirpId, err := uuid.Parse(req.PathValue("chirpID"))

	if err != nil {
		respondWithError(w, 422, "Invalid uuid given")
		return
	}

	chirp, err := cfg.Db.GetChirpById(req.Context(), chirpId)

	if err != nil {
		respondWithError(w, 404, "Error while getting chirp")
		return
	}

	respondWithJson(w, 200, types.Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	})
	return
}

func (cfg *ApiConfig) RefreshHandler(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	refresh, err := cfg.Db.GetTokenById(req.Context(), refreshToken)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	if refresh.RevokedAt.Valid {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	if time.Now().After(refresh.ExpiresAt) {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	token, err := auth.MakeJWT(refresh.UserID, cfg.JwtSecret, time.Hour*1)

	if err != nil {
		respondWithError(w, 500, "An error occured try again later")
		return
	}

	respondWithJson(w, 200, H{
		"token": token,
	})
	return
}

func (cfg *ApiConfig) RevokeHandler(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	refresh, err := cfg.Db.GetTokenById(req.Context(), refreshToken)

	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	err = cfg.Db.RevokeToken(req.Context(), database.RevokeTokenParams{
		RevokedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
		Token: refresh.Token,
	})

	if err != nil {
		respondWithError(w, 500, "An error occured try again later")
		return
	}

	respondWithJson(w, 204, nil)
	return
}

func (cfg *ApiConfig) PolkaWebhookHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	apiKey, err := auth.GetAPIKey(req.Header)

	if err != nil || apiKey != cfg.PolkaKey {
		respondWithError(w, 401, "Missing or wrong api key")
		return
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}

	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		respondWithError(w, 500, "Error decoding parameters")
		return
	}

	if params.Event != "user.upgraded" {
		respondWithJson(w, 204, nil)
		return
	}

	parsedID, _ := uuid.Parse(params.Data.UserID)

	_, err = cfg.Db.UpdateSub(req.Context(), database.UpdateSubParams{
		UpdatedAt:   time.Now(),
		IsChirpyRed: true,
		ID:          parsedID,
	})

	if err != nil {
		respondWithError(w, 404, "Error finding user")
		return
	}

	respondWithJson(w, 204, nil)
	return
}

func cleanInput(body string) string {
	prohibited := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}
	words := strings.Fields(body)
	var cleaned []string

	for _, word := range words {
		if _, found := prohibited[strings.ToLower(word)]; found {
			cleaned = append(cleaned, "****")
			continue
		}
		cleaned = append(cleaned, word)
	}

	return strings.Join(cleaned, " ")
}

func GetOrCreateRefreshToken(cfg *ApiConfig, req *http.Request, userID uuid.UUID) (database.RefreshToken, error) {
	var refresh database.RefreshToken
	var err error

	refresh, err = cfg.Db.GetTokenByUserId(req.Context(), userID)

	if err == nil {
		return refresh, nil
	}

	refreshString, err := auth.MakeRefreshToken()

	if err != nil {
		return refresh, err
	}

	refresh, err = cfg.Db.CreateToken(req.Context(), database.CreateTokenParams{
		Token:     refreshString,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UserID:    userID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})

	if err != nil {
		return refresh, err
	}

	return refresh, nil
}
