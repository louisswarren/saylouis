#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <monocypher.h>

#include "unified.h"

#define die(...) do { \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
		exit(1); \
	} while(0)

static
inline
void
nonce_inc(uint8_t nonce[24])
{
	for (int i = 0; i < 24 && ++nonce[i] == 0; ++i);
}

void
encrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile)
{
	uint8_t *buf;
	uint8_t ctr[24] = {0};
	size_t len;

	if (!(buf = malloc(BLOCKSIZE + 16)))
		die("Out of memory");

	while (len = fread(buf, 1, BLOCKSIZE, infile)) {
		if (ferror(infile))
			die("Error reading input");
		crypto_lock(buf + len, buf, key, ctr, buf, len);
		if (fwrite(buf, len + 16, 1, outfile) != 1)
			die("Write error");
		nonce_inc(ctr);
		if (len < BLOCKSIZE)
			break;
	}
	if (ferror(infile))
		die("Error reading input");
	/* Last block must always be a short block */
	if (!len) {
		/* Append a zero-length ciphertext */
		/* Documentation doesn't say mac can overlap in this case */
		crypto_lock(buf, buf + 16, key, ctr, buf + 16, 0);
		if (fwrite(buf, 16, 1, outfile) != 1)
			die("Write error");
	}
	crypto_wipe(buf, BLOCKSIZE + 16);
	free(buf);
}

void
decrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile)
{
	uint8_t *buf;
	uint8_t ctr[24] = {0};
	size_t len;

	if (!(buf = malloc(BLOCKSIZE + 16)))
		die("Out of memory");

	while ((len = fread(buf, 1, BLOCKSIZE + 16, infile)) == BLOCKSIZE + 16) {
		if (crypto_unlock(
			buf, key, ctr, buf + BLOCKSIZE, buf, BLOCKSIZE)
		) {
			die("Decryption failed");
		}
		if (fwrite(buf, BLOCKSIZE, 1, outfile) != 1)
			die("Write error");
		nonce_inc(ctr);
	}
	if (ferror(infile))
		die("Error reading input");
	if (!len) {
		die("Input truncated");
	} else if (len == 16) {
		if (crypto_unlock(
			buf + 16, key, ctr, buf, buf + 16, 0)
		) {
			die("Decryption failed");
		}
	} else {
		len -= 16;
		if (crypto_unlock(
			buf, key, ctr, buf + len, buf, len)
		) {
			die("Decryption failed");
		}
		if (fwrite(buf, len, 1, outfile) != 1)
			die("Write error");
		nonce_inc(ctr);
	}
	crypto_wipe(buf, BLOCKSIZE + 16);
	free(buf);
}

void
derive_key_pair(
	uint8_t d_public[32],
	uint8_t d_secret[32],
	const uint8_t *pwd,
	uint32_t pwdlen
)
{
	const uint32_t kdf_blocks = 512 * 1024;
	const uint32_t kdf_iterations = 3;
	const uint8_t kdf_salt[16] = {
		'l', 'o', 'u', 'i',
		's', '@', 'l', 's',
		'w', '.', 'n', 'z',
		31,  41,  59,  26,
	};

	/* If d_secret is NULL, create a temporary buffer for the secret key */
	uint8_t d_secret_internal[32];
	uint8_t *secret_buf = d_secret ? d_secret : d_secret_internal;

	void *work_area = calloc(kdf_blocks, 1024);
	if (!work_area)
		die("Failed to allocate work area");

	crypto_argon2i(
		secret_buf, 32,
		work_area,
		kdf_blocks, kdf_iterations,
		pwd, pwdlen,
		kdf_salt, sizeof(kdf_salt)
	);

	crypto_x25519_public_key(d_public, secret_buf);

	/* Wipe the d_secret_internal regardless if it was used (paranoid) */
	crypto_wipe(d_secret_internal, sizeof(d_secret_internal));
}

void
key_from_random(
	uint8_t key[32],
	uint8_t e_public_hidden[32],
	uint8_t seed[32],
	const uint8_t d_public[32]
)
{
	uint8_t e_secret[32];
	uint8_t e_public[32];
	crypto_blake2b_ctx bc;

	/* Create a new key pair along with a hidden public key */
	crypto_hidden_key_pair(e_public_hidden, e_secret, seed);
	crypto_hidden_to_curve(e_public, e_public_hidden);

	/* Create a shared key */
	crypto_x25519(key, e_secret, d_public);
	crypto_wipe(e_secret, sizeof(e_secret));

	/* Commit the shared key using the public keys */
	crypto_blake2b_general_init(&bc, 32, NULL, 0);
	crypto_blake2b_update(&bc, key, 32);
	crypto_blake2b_update(&bc, d_public, 32);
	crypto_blake2b_update(&bc, e_public, 32);
	crypto_blake2b_final(&bc, key); // Wipes bc

	/* Paranoia */
	crypto_wipe(e_public, sizeof(e_public));
}

void
key_from_secret(
	uint8_t key[32],
	const uint8_t e_public_hidden[32],
	const uint8_t d_secret[32]
)
{
	uint8_t d_public[32];
	uint8_t e_public[32];
	crypto_blake2b_ctx bc;

	/* Find the two public keys */
	crypto_hidden_to_curve(e_public, e_public_hidden);
	crypto_x25519_public_key(d_public, d_secret);
	/* d_public should be the same as LOUIS_PUBLIC_KEY */

	/* Create the shared key */
	crypto_x25519(key, d_secret, e_public);

	/* Commit the shared key using the public keys */
	crypto_blake2b_general_init(&bc, 32, NULL, 0);
	crypto_blake2b_update(&bc, key, 32);
	crypto_blake2b_update(&bc, d_public, 32);
	crypto_blake2b_update(&bc, e_public, 32);
	crypto_blake2b_final(&bc, key); // Wipes bc

	/* Paranoia */
	crypto_wipe(e_public, sizeof(e_public));
}

void
unhide_key(uint8_t public[32], uint8_t public_hidden[32])
{
	crypto_hidden_to_curve(public, public_hidden);
}
