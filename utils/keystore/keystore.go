package keystore

import (
	"os"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	pcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/aixoio/chat2me/utils/aeshelper"
	"github.com/aixoio/chat2me/utils/shahelper"
	"github.com/google/uuid"
)

// Returns true if the ./keys folder is found
func CheckIfKeyStoreDBExists() bool {
  if _, err := os.Stat("./keys"); os.IsNotExist(err) {
    return false
  }
  return true
}

func GenerateKeys() (*pcrypto.Key, error) {
  pgpCR := pcrypto.PGPWithProfile(profile.RFC9580())

  pgpKeyGenHandle := pgpCR.KeyGeneration().AddUserId(uuid.NewString(), "").New()

  pgpEcKeyHigh, err := pgpKeyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)
  if err != nil {
    return nil, err
  }
  return pgpEcKeyHigh, nil
}

func SavePGPKeys(aespassword string, priKey *pcrypto.Key) error {
  aeskey := shahelper.Sha256ToBytes([]byte(aespassword))

  pKey, err := priKey.Armor()
  if err != nil {
    return err
  }

  pubKey, err := priKey.GetArmoredPublicKey()
  if err != nil {
    return err
  }

  ePKey, err := aeshelper.AesGCMEncrypt(aeskey, []byte(pKey))
  if err != nil {
    return err
  }

  ePubKey, err := aeshelper.AesGCMEncrypt(aeskey, []byte(pubKey))
  if err != nil {
    return err
  }

  if err := os.Mkdir("./keys", 0755); err != nil {
    return err
  }

  if err := os.WriteFile("./keys/pri.key", ePKey, 0644); err != nil {
    return err
  }

  if err := os.WriteFile("./keys/pub.key", ePubKey, 0644); err != nil {
    return err
  }

  return nil
}

