struct __attribute__((packed)) keyfile {
	uint8_t preamble[32];
	uint8_t nb_blocks_raw[4];
	uint8_t nb_passes_raw[4];
	uint8_t salt[16];
	uint8_t nonce[24];
	uint8_t key_encrypted[32];
	uint8_t mac[16];
};

int
getrandom_atomic(void *buf, size_t buflen)
{
	return getrandom(buf, buflen, 0) != buflen;
}

uint32_t
u32_from_bytes(const uint8_t bytes[4])
{
	return (uint32_t)bytes[3] << 24
	     | (uint32_t)bytes[2] << 16
	     | (uint32_t)bytes[1] <<  8
	     | (uint32_t)bytes[0] <<  0;
}

void
bytes_from_u32(uint8_t bytes[4], uint32_t n)
{
	bytes[3] = n >> 24;
	bytes[2] = n >> 16;
	bytes[1] = n >>  8;
	bytes[0] = n >>  0;
}

int
read_key(uint8_t key[32], const uint8_t *pass, uint32_t pass_size, FILE *f)
{
	struct keyfile c;
	uint8_t derived_secret[32];
	uint8_t *workarea;

	if (!fread(&c, sizeof(c), 1, f))
		return 1;

	uint32_t blocks = u32_from_bytes(c.nb_blocks_raw);
	uint32_t passes = u32_from_bytes(c.nb_passes_raw);

	if (!blocks || !passes)
		return 1;

	if (!(workarea = calloc(blocks, 1024)))
		return 1;

	crypto_argon2_config cfg = {
		.algorithm = CRYPTO_ARGON2_D,
		.nb_blocks = blocks,
		.nb_passes = passes,
		.nb_lanes  = 1};

	crypto_argon2_inputs inputs = {
		.pass = pass,
		.salt = c.salt,
		.pass_size = pass_size,
		.salt_size = sizeof(c.salt)};

	crypto_argon2(
		derived_secret, sizeof(derived_secret),
		workarea,
		cfg,
		inputs,
		crypto_argon2_no_extras);
	free(workarea);

	int unlock_status = crypto_aead_unlock(
		key,
		c.mac,
		derived_secret,
		c.nonce,
		c.preamble,
		c.nonce - c.preamble,
		c.key_encrypted,
		sizeof(c.key_encrypted));
	crypto_wipe(derived_secret, sizeof(derived_secret));

	return unlock_status;
}

int
write_key(
	const uint8_t key[32],
	const uint8_t *pass,
	uint32_t pass_size,
	const uint8_t *preamble,
	uint32_t preamble_size,
	uint32_t nb_blocks,
	uint32_t nb_passes,
	FILE *f)
{
	struct keyfile c = {0};
	uint8_t derived_secret[32];
	uint8_t *workarea;

	if (preamble_size > sizeof(c.preamble)) {
		memcpy(c.preamble, preamble, sizeof(c.preamble));
	} else {
		memcpy(c.preamble, preamble, preamble_size);
	}

	bytes_from_u32(c.nb_blocks_raw, nb_blocks);
	bytes_from_u32(c.nb_passes_raw, nb_passes);

	/* Random salt + nonce */
	if (getrandom_atomic(c.salt, c.key_encrypted - c.salt))
		return 1;

	if (!(workarea = calloc(nb_blocks, 1024)))
		return 1;

	crypto_argon2_config cfg = {
		.algorithm = CRYPTO_ARGON2_D,
		.nb_blocks = nb_blocks,
		.nb_passes = nb_passes,
		.nb_lanes  = 1};

	crypto_argon2_inputs inputs = {
		.pass = pass,
		.salt = c.salt,
		.pass_size = pass_size,
		.salt_size = sizeof(c.salt)};

	crypto_argon2(
		derived_secret, sizeof(derived_secret),
		workarea,
		cfg,
		inputs,
		crypto_argon2_no_extras);
	free(workarea);

	crypto_aead_lock(
		c.key_encrypted,
		c.mac,
		derived_secret,
		c.nonce,
		c.preamble,
		c.nonce - c.preamble,
		key,
		sizeof(c.key_encrypted));
	crypto_wipe(derived_secret, sizeof(derived_secret));

	if (!fwrite(&c, sizeof(c), 1, f))
		return 1;

	return 0;
}
