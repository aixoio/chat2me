package shahelper

import "crypto/sha256"

func Sha256ToBytes(dat []byte) []byte {
	hash := sha256.Sum256([]byte(dat))
  return hash[:]
}
