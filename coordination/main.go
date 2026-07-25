package main

import (
	"log"

	"github.com/devlup-labs/Ghostwire/coordination-server/routes"
)

func main() {
	srv := routes.CreateServer()
	log.Fatal(srv.ListenAndServe())
}
