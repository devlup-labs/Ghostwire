package main

import (
	"log"

	"github.com/devlup-labs/Ghostwire/coordination-server/database"
	"github.com/devlup-labs/Ghostwire/coordination-server/routes"
)

func main() {
	err := database.InitializeDatabase("test.db")
	if err != nil {
		log.Fatal(err)
	}
	srv := routes.CreateServer()
	log.Fatal(srv.ListenAndServe())
}
