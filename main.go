package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/Bemax3/chirpy/internal/database"
	h "github.com/Bemax3/chirpy/internal/handlers"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {

	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbUrl)

	if err != nil {
		fmt.Println("Cannot connect to database")
		os.Exit(1)
	}

	dbQueries := database.New(db)

	fmt.Println("Database initialized: ", dbQueries)

	cfg := &h.ApiConfig{
		Db:             dbQueries,
		FileserverHits: atomic.Int32{},
		JwtSecret:      jwtSecret,
		PolkaKey:       polkaKey,
	}

	// File Server Handler
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app", cfg.MiddlewareMetrics(http.FileServer(http.Dir(".")))))

	// Api Routes
	// -- Webhooks
	mux.HandleFunc("POST /api/polka/webhooks", cfg.PolkaWebhookHandler)

	// -- Health
	mux.HandleFunc("GET /api/healthz", h.HealthzHandler)

	// -- Users
	mux.HandleFunc("POST /api/login", cfg.LoginHandler)
	mux.HandleFunc("POST /api/users", cfg.CreateUserHandler)
	mux.HandleFunc("PUT /api/users", cfg.UpdateUserHandler)
	mux.HandleFunc("POST /api/refresh", cfg.RefreshHandler)
	mux.HandleFunc("POST /api/revoke", cfg.RevokeHandler)

	// -- Chirps
	mux.HandleFunc("POST /api/chirps", cfg.CreateChirpHandler)
	mux.HandleFunc("GET /api/chirps", cfg.GetChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.GetChirpHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.DeleteChirpHandler)

	// Admin Routes
	mux.HandleFunc("GET /admin/metrics", cfg.MetricsHandler)
	mux.HandleFunc("POST /admin/reset", cfg.ResetHandler)

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Fatal(server.ListenAndServe())
}
