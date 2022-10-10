#include <stdio.h>
#include <stdlib.h>

#include <sys/random.h>

#include <monocypher.h>

#include "common.h"

#include "my_public_key.h"

static
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

int
main(void)
{
	uint8_t seed[32];
	uint8_t hidden[32];
	uint8_t public[32];
	uint8_t secret[32];
	uint8_t shared[32];

	/* Get a new key pair from a random seed */
	if (getrandom(seed, sizeof(seed), 0) != sizeof(seed))
		die("Failed to seed a new key");
	crypto_hidden_key_pair(hidden, secret, seed);
	crypto_wipe(seed, sizeof(seed));
	crypto_hidden_to_curve(public, hidden);
	show_fingerprint(public);

	crypto_x25519(shared, secret, my_public_key);
	shared_secret_key_commit(shared, my_public_key, public);
	crypto_wipe(secret, sizeof(secret));

	/* Output the hidden public key */
	if (fwrite(hidden, sizeof(hidden), 1, stdout) != 1)
		die("Write error");

	encrypt_blocks(shared, stdin, stdout);
	crypto_wipe(shared, sizeof(shared));

	return 0;
}
