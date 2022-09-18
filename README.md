saylouis
========

Compilation
-----------

Use Argon2i key derivation to generate my public key from a passphrase.
The public key is then hard-coded into the `saylouis` source before compilation.

Encryption
----------

Generate a new X25519 key pair. Perform X25519 key exchange with my stored
public key and hash the result to produce a shared secret. Use this shared
secret and the public key for authenticated encryption via *XChaCha20*. Output
a hidden form of the public key (indistinguishable from random noise), a MAC,
and the ciphertext. Also output a fingerprint of the public key.

Details:

1. My public key `lp` is hard-coded into the binary.
2. Generate a 32-byte random seed `seed`.
3. Use `crypto_hidden_key_pair(uhp, uk, seed)`
   to get a (hidden) public key `uhp` and a private key `uk`.
4. Use `crypto_x25519(rs, uk, lp)` to get secret `rs`, and then hash it using
   `ss = BLAKE2b(rs || uhp || lp)` to get the final shared secret.
5. Output `uhp`.
6. Input at most `blocksize` bytes.
7. Call `crypto_lock_aead` on `ss`, `plaintext`, using a count
   (starting at zero) of the blocks as the nonce,
	 to get the `ciphertext` and `mac`.
8. Output `mac || ciphertext`. If there's more input to handle, go to 6.
9. Display a fingerprint of `uhp`.

Decryption
----------

Read the public key from the input, display the fingerprint and confirm it's
okay to continue. Use Argon2i key derivation to compute my public and private
key from a passphrase. Authenticate the ciphertext using the mac, decrypt using the nonce and my secret key.
