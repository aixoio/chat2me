package main

import (
	"fmt"

	"github.com/aixoio/chat2me/server/keystore"
)

func main() {
  fmt.Println("Checking for database...")
  if !keystore.CheckIfKeyStoreDBExists() {
    fmt.Println("The database file was not found generating...")
  }
}

