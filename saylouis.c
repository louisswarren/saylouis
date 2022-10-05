#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/random.h>

#include <monocypher.h>

#include "common.h"

#include "my_public_key.h"


#define BLOCKSIZE 20

static
void
nonce_inc(uint8_t ctr[24])
{
	for (int i = 0; i < 24 && ++ctr[i] == 0; ++i);
}

static
void
show_fingerprint(uint8_t hidden[32])
{
	for (int i = 0; i < 32; ++i)
		fprintf(stderr, "%x", hidden[i]);
	fprintf(stderr, "\n");
}

int
main(void)
{
	uint8_t seed[32];
	uint8_t hidden[32];
	uint8_t public_key[32];
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
	crypto_hidden_to_curve(public_key, hidden);
	show_fingerprint(public_key);

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

	while (len = fread(buf, 1, BLOCKSIZE, stdin)) {
		if (ferror(stdin))
			die("Error reading input.\n");
		crypto_lock(buf + len, buf, shared_secret, ctr, buf, len);
		if (fwrite(buf, len + 16, 1, stdout) != 1)
			die("Write error.\n");
		nonce_inc(ctr);
		if (len < BLOCKSIZE)
			break;
	}
	if (ferror(stdin))
		die("Error reading input.\n");
	/* Last block must always be a short block */
	if (!len) {
		/* Append a zero-length ciphertext */
		/* Documentation doesn't say mac can overlap in this case */
		crypto_lock(buf, buf + 16, shared_secret, ctr, buf + 16, 0);
		if (fwrite(buf, 16, 1, stdout) != 1)
			die("Write error.\n");
	}
	crypto_wipe(shared_secret, sizeof(shared_secret));

	return 0;
}
