#include <stdio.h>
#include <stdlib.h>

#include <sys/random.h>

#include <monocypher.h>

#include "unified.h"

#include "my_public_key.h"

#define die(...) do { \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
		exit(1); \
	} while(0)

static
void
show_fingerprint(const uint8_t public[32])
{
	for (int i = 0; i < 32; ++i)
		fprintf(stderr, "%x", public[i]);
	fprintf(stderr, "\n");
}

int
main(void)
{
	uint8_t seed[32];
	uint8_t hidden[32];
	uint8_t public[32];
	uint8_t shared[32];

	/* Get a new key pair from a random seed */
	if (getrandom(seed, sizeof(seed), 0) != sizeof(seed))
		die("Failed to seed a new key");


	key_from_random(shared, hidden, seed, my_public_key);

	fprintf(stderr, "Encrypting with public key: ");
	unhide_key(public, hidden);
	show_fingerprint(public);
	fflush(stderr);

	/* Output the hidden public key */
	if (fwrite(hidden, sizeof(hidden), 1, stdout) != 1)
		die("Write error");

	encrypt_blocks(shared, stdin, stdout);
	crypto_wipe(shared, sizeof(shared));

	return 0;
}
