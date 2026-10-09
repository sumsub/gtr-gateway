package sumsub

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Optional PGP payload encryption (contract §2.1).
const (
	EncryptionHeader      = "X-Encryption"
	EncryptionHeaderValue = "true"
)

const maxPlaintextBytes = 1 << 20

// DecryptError is reported to Sumsub as 422 crypto_failed.
type DecryptError struct {
	Message string
	Err     error
}

func (e *DecryptError) Error() string { return e.Message }
func (e *DecryptError) Unwrap() error { return e.Err }

// DecryptorOptions configures a Decryptor.
type DecryptorOptions struct {
	// PrivateKeys holds one or more ASCII-armored gateway private keys; during a rotation add the new key after the old one.
	PrivateKeys string
	// Passphrase unlocks every encrypted private key.
	Passphrase string
	// SumsubPublicKey is the ASCII-armored key every encrypted request must be signed with.
	SumsubPublicKey string
	// Tolerance is the accepted age of the Sumsub signature; zero means DefaultTimestampTolerance.
	Tolerance time.Duration
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Decryptor decrypts Sumsub requests with the gateway private keys and checks the Sumsub signature and its age.
type Decryptor struct {
	keyring   openpgp.EntityList
	sumsub    openpgp.EntityList
	tolerance time.Duration
	now       func() time.Time
}

// NewDecryptor reads and unlocks the gateway private keys and the Sumsub public key.
func NewDecryptor(options DecryptorOptions) (*Decryptor, error) {
	private, err := readKeyRing(options.PrivateKeys)
	if err != nil {
		return nil, fmt.Errorf("gateway PGP private key is not an ASCII-armored PGP private key: %w", err)
	}
	for _, entity := range private {
		if err := unlock(entity, options.Passphrase); err != nil {
			return nil, err
		}
	}
	sumsub, err := readKeyRing(options.SumsubPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Sumsub PGP public key is not an ASCII-armored PGP public key: %w", err)
	}
	keyring := append(openpgp.EntityList{}, private...)
	keyring = append(keyring, sumsub...)
	decryptor := &Decryptor{keyring: keyring, sumsub: sumsub, tolerance: options.Tolerance, now: options.Now}
	if decryptor.tolerance <= 0 {
		decryptor.tolerance = DefaultTimestampTolerance
	}
	if decryptor.now == nil {
		decryptor.now = time.Now
	}
	return decryptor, nil
}

// Decrypt returns the plaintext of a message encrypted to the gateway key and signed by Sumsub.
func (d *Decryptor) Decrypt(armored []byte) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader(armored))
	if err != nil {
		return nil, &DecryptError{Message: "Request body is not an ASCII-armored PGP message", Err: err}
	}
	details, err := openpgp.ReadMessage(block.Body, d.keyring, nil, nil)
	if err != nil {
		return nil, &DecryptError{Message: "Request body cannot be decrypted", Err: err}
	}
	plaintext, err := io.ReadAll(io.LimitReader(details.UnverifiedBody, maxPlaintextBytes+1))
	if err != nil {
		return nil, &DecryptError{Message: "Request body cannot be decrypted", Err: err}
	}
	if len(plaintext) > maxPlaintextBytes {
		return nil, &DecryptError{Message: "Request body is too large"}
	}
	if details.SignatureError != nil {
		return nil, &DecryptError{Message: "Request signature is invalid", Err: details.SignatureError}
	}
	if !details.IsSigned || details.SignedBy == nil || !d.isSumsub(details.SignedBy.Entity) {
		return nil, &DecryptError{Message: "Request body is not signed by Sumsub"}
	}
	if details.Signature == nil {
		return nil, &DecryptError{Message: "Request signature is invalid"}
	}
	if d.now().Sub(details.Signature.CreationTime).Abs() > d.tolerance {
		return nil, &DecryptError{Message: "Request signature is outside the allowed time window; check the gateway clock"}
	}
	return plaintext, nil
}

func (d *Decryptor) isSumsub(entity *openpgp.Entity) bool {
	for _, candidate := range d.sumsub {
		if candidate == entity {
			return true
		}
	}
	return false
}

// NormalizeArmored accepts a key pasted into an environment variable as one line with backslash-n sequences.
func NormalizeArmored(value string) string {
	if strings.Contains(value, "\n") {
		return value
	}
	return strings.ReplaceAll(value, `\n`, "\n")
}

var armoredBlock = regexp.MustCompile(`(?s)-----BEGIN PGP [A-Z ]+-----.*?-----END PGP [A-Z ]+-----`)

func readKeyRing(armored string) (openpgp.EntityList, error) {
	blocks := armoredBlock.FindAllString(NormalizeArmored(armored), -1)
	if len(blocks) == 0 {
		return nil, errors.New("no key found")
	}
	var entities openpgp.EntityList
	for _, block := range blocks {
		keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(block))
		if err != nil {
			return nil, err
		}
		entities = append(entities, keys...)
	}
	return entities, nil
}

func unlock(entity *openpgp.Entity, passphrase string) error {
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
			return fmt.Errorf("passphrase does not unlock the gateway PGP private key: %w", err)
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			if err := subkey.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
				return fmt.Errorf("passphrase does not unlock the gateway PGP private key: %w", err)
			}
		}
	}
	return nil
}
