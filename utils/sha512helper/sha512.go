package sha512helper

import "crypto/sha512"

func Sha512ToBytes(dat []byte) []byte {
	hash := sha512.Sum512([]byte(dat))
  return hash[:]
}
