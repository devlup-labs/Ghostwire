package routes

import (
	"fmt"
	"net/http"
	"time"

	"github.com/devlup-labs/Ghostwire/coordination-server/routes/general"
	"github.com/gorilla/mux"
)

func CreateServer() (srv *http.Server) {
	srv = &http.Server{
		Handler:      createRouter(),
		Addr:         "127.0.0.1:8000", // TODO: Change this to be based on env vars
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	return
}

func createRouter() (router *mux.Router) {
	router = mux.NewRouter()

	v1subrouter := router.PathPrefix("/api/v1").Subrouter()
	v1subrouter.HandleFunc("/login", general.LoginHandler)
	v1subrouter.HandleFunc("/connect", general.ConnectHandler)
	v1subrouter.HandleFunc("/checkin", general.CheckinHandler)
	v1subrouter.HandleFunc("/register", general.RegisterHandler)

	router.HandleFunc("/api", versionCheckHandler)
	router.HandleFunc("/", rootHandler)

	return
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func versionCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ghostwire v%s API v%s", "0.0.0", "1")
}
