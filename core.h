int
getrandom_atomic(void *buf, size_t buflen)
{
	return getrandom(buf, buflen, 0) != buflen;
}

enum keyfile_offset {
	/* Covered by AD */
	KEYFILE_PREAMBLE        =   0, // 32 bytes
	KEYFILE_BLOCKS          =  32, // 4 bytes BE
	KEYFILE_PASSES          =  36, // 4 bytes BE
	KEYFILE_SALT            =  40, // 16 bytes
	/* End of AD */
	KEYFILE_NONCE           =  56, // 24 bytes
	KEYFILE_KEY_ENCRYPTED   =  80, // 32 bytes
	KEYFILE_MAC             = 112, // 16 bytes
	KEYFILE_END             = 128,
};

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
read_key(uint8_t key[32], const uint8_t *pass, uint32_t pass_size, FILE *f) {
	uint8_t contents[KEYFILE_END];
	uint8_t derived_secret[32];
	uint8_t *workarea;

	if (!fread(contents, sizeof(contents), 1, f))
		return 1;

	uint32_t blocks = u32_from_bytes(contents + KEYFILE_BLOCKS);
	uint32_t passes = u32_from_bytes(contents + KEYFILE_PASSES);

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
		.salt = contents + KEYFILE_SALT,
		.pass_size = pass_size,
		.salt_size = KEYFILE_NONCE - KEYFILE_SALT};

	crypto_argon2(
		derived_secret, sizeof(derived_secret),
		workarea,
		cfg,
		inputs,
		crypto_argon2_no_extras);
	free(workarea);

	int unlock_status = crypto_aead_unlock(
		key,
		contents + KEYFILE_MAC,
		derived_secret,
		contents + KEYFILE_NONCE,
		contents + KEYFILE_PREAMBLE,
		KEYFILE_NONCE - KEYFILE_PREAMBLE,
		contents + KEYFILE_KEY_ENCRYPTED,
		KEYFILE_MAC - KEYFILE_KEY_ENCRYPTED);
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
	uint8_t contents[KEYFILE_END] = {0};
	uint8_t derived_secret[32];
	uint8_t *workarea;

	memcpy(
		contents + KEYFILE_PREAMBLE,
		preamble,
		preamble_size > 32 ? 32 : preamble_size);

	bytes_from_u32(contents + KEYFILE_BLOCKS, nb_blocks);
	bytes_from_u32(contents + KEYFILE_PASSES, nb_passes);

	/* Random salt + nonce */
	size_t randlen = KEYFILE_KEY_ENCRYPTED - KEYFILE_SALT;
	if (getrandom_atomic(contents + KEYFILE_SALT, randlen))
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
		.salt = contents + KEYFILE_SALT,
		.pass_size = pass_size,
		.salt_size = KEYFILE_NONCE - KEYFILE_SALT};

	crypto_argon2(
		derived_secret, sizeof(derived_secret),
		workarea,
		cfg,
		inputs,
		crypto_argon2_no_extras);
	free(workarea);

	crypto_aead_lock(
		contents + KEYFILE_KEY_ENCRYPTED,
		contents + KEYFILE_MAC,
		derived_secret,
		contents + KEYFILE_NONCE,
		contents + KEYFILE_PREAMBLE,
		KEYFILE_NONCE - KEYFILE_PREAMBLE,
		key,
		KEYFILE_MAC - KEYFILE_KEY_ENCRYPTED);
	crypto_wipe(derived_secret, sizeof(derived_secret));

	if (!fwrite(contents, sizeof(contents), 1, f))
		return 1;

	return 0;
}
