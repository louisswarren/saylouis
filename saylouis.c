#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/random.h>

#include <monocypher.h>

#include "my_public_key.h"

#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while(0)

#define BLOCKSIZE (64 * 1024)

static
void
nonce_inc(uint8_t ctr[24])
{
	for (int i = 0; i < 24 && ++ctr[i] == 0; ++i);
}

int
main(void)
{
	uint8_t seed[32];
	uint8_t hidden[32];
	uint8_t secret_key[32];
	uint8_t shared_secret[32];

	uint8_t buf[BLOCKSIZE + 16];
	uint8_t ctr[24] = {0};
	size_t len;

	crypto_blake2b_ctx blake_ctx;

	/* Get a new key pair from a random seed */
	if (getrandom(seed, sizeof(seed), 0) != sizeof(seed))
		die("Failed to seed a new key.\n");
	crypto_hidden_key_pair(hidden, secret_key, seed);
	crypto_wipe(seed, sizeof(seed));

	/* Generate a raw shared secret */
	crypto_x25519(shared_secret, secret_key, my_public_key);
	crypto_wipe(secret_key, sizeof(secret_key));

	/* Hash the shared secret with the public keys */
	crypto_blake2b_general_init(&blake_ctx,
		sizeof(shared_secret), NULL, 0);
	crypto_blake2b_update(&blake_ctx,
		shared_secret, sizeof(shared_secret));
	crypto_blake2b_update(&blake_ctx,
		hidden, sizeof(hidden));
	crypto_blake2b_update(&blake_ctx,
		my_public_key, sizeof(my_public_key));
	crypto_blake2b_final(&blake_ctx,
		shared_secret);

	/* Output the hidden public key */
	if (fwrite(hidden, sizeof(hidden), 1, stdout) != 1)
		die("Write error.\n");

	while (!feof(stdin)) {
		len = fread(buf, 1, BLOCKSIZE, stdin);
		if (ferror(stdin))
			die("Error reading input.\n");
		if (!len)
			break;
		crypto_lock(buf + len, buf, shared_secret, ctr, buf, len);
		if (fwrite(buf, len + 16, 1, stdout) != 1)
			die("Write error.\n");
		nonce_inc(ctr);
	}
	/* Last block must always be a short write */
	if (len % BLOCKSIZE == 0) {
		/* Append a zero-length ciphertext */
		crypto_lock(buf, buf + 16, shared_secret, ctr, buf + 16, 0);
		if (fwrite(buf, 16, 1, stdout) != 1)
			die("Write error.\n");
	}

	return 0;
}
