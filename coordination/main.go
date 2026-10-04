package main

import (
	"log"
	"os"

	"github.com/devlup-labs/Ghostwire/coordination-server/database"
	"github.com/devlup-labs/Ghostwire/coordination-server/routes"
	"github.com/devlup-labs/Ghostwire/coordination-server/routes/general"
)

func main() {
	err := database.InitializeDatabase("test.db")
	if err != nil {
		log.Fatal(err)
	}

	clientID := os.Getenv("GOOGLE_CLIENT_ID")

	if clientID == "" {
		log.Fatal("GOOGLE_CLIENT_ID is not set")
	}
	if err := general.InitializeOIDC(clientID); err != nil {
		log.Fatal(err)
	}

	srv := routes.CreateServer()
	log.Fatal(srv.ListenAndServe())
}
