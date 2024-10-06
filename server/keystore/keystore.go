package keystore

import "os"

// Returns true if the ./keys folder is found
func CheckIfKeyStoreDBExists() bool {
  if _, err := os.Stat("/path/to/whatever"); os.IsNotExist(err) {
    return false
  }
  return true
}
