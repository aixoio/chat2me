package main

import (
	"fmt"

	"github.com/aixoio/chat2me/utils/input"
	"github.com/aixoio/chat2me/utils/keystore"
)

func main() {
  fmt.Println("Checking for database...")
  if !keystore.CheckIfKeyStoreDBExists() {
    keypass, err := input.Ask("Choose a password for your keys:")
    if err != nil {
      panic(err)
    }
    
    fmt.Println("The database file was not found generating...")

    pgpKey, err := keystore.GenerateKeys()
    if err != nil {
      panic(err)
    }

    if err := keystore.SavePGPKeys(keypass, pgpKey); err != nil {
      panic(err)
    }
  }
}

