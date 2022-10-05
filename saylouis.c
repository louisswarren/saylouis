#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/random.h>

#include <monocypher.h>

#include "common.h"

#include "my_public_key.h"

int
main(void)
{
	uint8_t seed[32];
	uint8_t hidden[32];
	uint8_t public[32];
	uint8_t secret[32];
	uint8_t shared[32];

	uint8_t buf[BLOCKSIZE + 16];
	uint8_t ctr[24] = {0};
	size_t len;

	/* Get a new key pair from a random seed */
	if (getrandom(seed, sizeof(seed), 0) != sizeof(seed))
		die("Failed to seed a new key");
	crypto_hidden_key_pair(hidden, secret, seed);
	crypto_wipe(seed, sizeof(seed));
	crypto_hidden_to_curve(public, hidden);
	show_fingerprint(public);

	key_exchange(shared, my_public_key, public, secret);
	crypto_wipe(secret, sizeof(secret));

	/* Output the hidden public key */
	if (fwrite(hidden, sizeof(hidden), 1, stdout) != 1)
		die("Write error");

	while (len = fread(buf, 1, BLOCKSIZE, stdin)) {
		if (ferror(stdin))
			die("Error reading input");
		crypto_lock(buf + len, buf, shared, ctr, buf, len);
		if (fwrite(buf, len + 16, 1, stdout) != 1)
			die("Write error");
		nonce_inc(ctr);
		if (len < BLOCKSIZE)
			break;
	}
	if (ferror(stdin))
		die("Error reading input");
	/* Last block must always be a short block */
	if (!len) {
		/* Append a zero-length ciphertext */
		/* Documentation doesn't say mac can overlap in this case */
		crypto_lock(buf, buf + 16, shared, ctr, buf + 16, 0);
		if (fwrite(buf, 16, 1, stdout) != 1)
			die("Write error");
	}
	crypto_wipe(shared, sizeof(shared));

	return 0;
}
