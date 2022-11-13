#include "unified.h"

void
encrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile)
{}

int
decrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile)
{}

void
derive_key_pair(
	uint8_t d_public[32],
	uint8_t d_secret[32],
	const uint8_t *pwd,
	uint32_t pwdlen
)
{}

void
key_from_random(
	uint8_t key[32],
	uint8_t e_hidden_public[32],
	const uint8_t seed[32]
)
{}

void
key_from_secret(
	uint8_t key[32],
	const uint8_t e_hidden_public[32],
	const uint8_t d_secret[32],
)
{}

void
unhide_key(uint8_t public_key[32], uint8_t hidden_public_key[32])
{}
