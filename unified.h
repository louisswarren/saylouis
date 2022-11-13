void encrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile);
int decrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile);

/* Derive decryption key pair (secret can be NULL if not needed). */
void derive_key_pair(
	uint8_t d_public[32],
	uint8_t d_secret[32],
	const uint8_t *pwd,
	uint32_t pwdlen
);

/* Create a new key for encryption from a random seed */
void key_from_random(
	uint8_t key[32],
	uint8_t e_hidden_public[32],
	const uint8_t seed[32]
);

/* Compute key for decryption from secret key and hidden encryption key */
void key_from_secret(
	uint8_t key[32],
	const uint8_t e_hidden_public[32],
	const uint8_t d_secret[32],
);

void unhide_key(uint8_t public_key[32], uint8_t hidden_public_key[32]);
