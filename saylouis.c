#include <sys/random.h>

#include "my_public_key.h"

#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while(0)

#define BLOCKSIZE (64 * 1024)

int
main(void)
{
	uint8_t seed[32];
	uint8_t hidden[32];
	uint8_t secret_key[32];
	uint8_t shared_secret[32];

	/* Get a new key pair from a random seed */
	if (getrandom(seed, sizeof(seed)) != sizeof(seed))
		die("Failed to seed a new key.\n");
	crypto_hidden_key_pair(hidden, secret_key, seed);
	crypto_wipe(seed, sizeof(seed));

	/* Generate a raw shared secret */
	crypto_x25519(shared_secret, secret_key, my_public_key);
	crypto_wipe(secret_key);

	/* Hash the shared secret with the public keys */
	crypto_blake_2b_general_init(&blake_ctx,
		sizeof(shared_secret), NULL, 0);
	crypto_blake_2b_update(&blake_ctx,
		raw_shared_secret, sizeof(raw_shared_secret);
	crypto_blake_2b_update(&blake_ctx,
		hidden, sizeof(hidden));
	crypto_blake_2b_update(&blake_ctx,
		my_public_key, sizeof(my_public_key));
	crypto_blake_2b_final(&blake_ctx,
		shared_secret);

	/* Output the hidden public key */
	fwrite(hidden, sizeof(hidden), 1, stdout);

	return 0;
}
