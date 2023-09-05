package cosigner

// ICosignerSecurity is an interface for the security layer of the cosigner.
type ICosignerSecurity interface {
	// GetID returns the ID of the cosigner.
	GetID() int

	// EncryptAndSign encrypts the nonce and signs it for authentication.
	EncryptAndSign(
		id int,
		noncePub []byte,
		nonceShare []byte,
	) (WrappedNonce, error)

	// DecryptAndVerify decrypts the nonce and verifies the signature to authenticate the source cosigner.
	DecryptAndVerify(
		id int,
		encryptedNoncePub []byte,
		encryptedNonceShare []byte,
		signature []byte,
	) (noncePub []byte, nonceShare []byte, err error)
}
