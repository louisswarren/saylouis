#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <monocypher.h>

#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while(0)

#define BLOCKSIZE 20

static
void
nonce_inc(uint8_t ctr[24])
{
	for (int i = 0; i < 24 && ++ctr[i] == 0; ++i);
}


static
int
set_no_echo(struct termios *prev)
{
	struct termios term_noecho;
	if (tcgetattr(0, prev))
		return 1;
	term_noecho = *prev;
	term_noecho.c_lflag &= (tcflag_t)~ECHO;
	if (tcsetattr(0, TCSAFLUSH, &term_noecho))
		return 1;
	return 0;
}

static
uint32_t
read_password(uint8_t *buf, uint32_t bufsize)
{
	uint32_t password_len = 0;
	struct termios term_old;

	if (set_no_echo(&term_old)) {
		buf = fgets(buf, (int)bufsize, stdin);
	} else {
		fprintf(stderr, "Passphrase (Echo off): ");
		buf = fgets(buf, (int)bufsize, stdin);
		(void)tcsetattr(0, TCSAFLUSH, &term_old);
	}

	if (!buf)
		die("Failed to read password.\n");

	password_len = (uint32_t)strlen(buf);

	if (password_len + 1 == bufsize)
		die("Password was truncated.\n");

	if (password_len && buf[password_len - 1] == '\n')
		buf[password_len-- - 1] = '\0';

	if (!password_len)
		die("Password was empty.\n");

	return password_len;
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
	/* Configuration options */
	uint32_t nb_blocks = 512 * 1024;
	uint32_t nb_iterations = 3;
	uint8_t salt[16] = {
		/* Generated by fair dice roll. Guaranteed to be random. */
		0x77, 0xe4, 0xd7, 0x76, 0xc5, 0xe1, 0x0e, 0xd8,
		0x09, 0xfa, 0xb5, 0x74, 0xd6, 0x3c, 0xd4, 0xfc
	};
	/* End of configuration options */

	uint8_t public_key[32];
	uint8_t secret_key[32];
	void *work_area = NULL;
	uint8_t password[1024] = "test";
	uint32_t password_len = 4;

	uint8_t hidden[32];
	uint8_t eph_public_key[32];
	uint8_t shared_secret[32];
	crypto_blake2b_ctx blake_ctx;

	uint8_t buf[BLOCKSIZE + 16];
	uint8_t ctr[24] = {0};
	size_t len;

	if (!(work_area = calloc(nb_blocks, 1024)))
		die("Failed to allocate work area.\n");

//	password_len = read_password(password, sizeof(password));
//

	crypto_argon2i(
		secret_key, sizeof(secret_key),
		work_area,
		nb_blocks, nb_iterations,
		password, password_len,
		salt, sizeof(salt)
	);
	crypto_wipe(password, sizeof(password));
	crypto_x25519_public_key(public_key, secret_key);

	if (fread(hidden, sizeof(hidden), 1, stdin) != 1)
		die("Read error.\n");
	crypto_hidden_to_curve(eph_public_key, hidden);
	show_fingerprint(eph_public_key);

	/* Generate a raw shared secret */
	crypto_x25519(shared_secret, secret_key, eph_public_key);
	crypto_wipe(secret_key, sizeof(secret_key));

	/* Hash the shared secret with the public keys */
	crypto_blake2b_general_init(&blake_ctx,
		sizeof(shared_secret), NULL, 0);
	crypto_blake2b_update(&blake_ctx,
		shared_secret, sizeof(shared_secret));
	crypto_blake2b_update(&blake_ctx,
		hidden, sizeof(hidden));
	crypto_blake2b_update(&blake_ctx,
		public_key, sizeof(public_key));
	crypto_blake2b_final(&blake_ctx,
		shared_secret);

	while ((len = fread(buf, 1, BLOCKSIZE + 16, stdin)) == BLOCKSIZE + 16) {
		fprintf(stderr, "Loop: decrypt block\n");
		if (crypto_unlock(
			buf, shared_secret, ctr, buf + BLOCKSIZE, buf, BLOCKSIZE)
		) {
			die("Decryption failed.\n");
		}
		if (fwrite(buf, BLOCKSIZE, 1, stdout) != 1)
			die("Write error.\n");
		nonce_inc(ctr);
	}
	fprintf(stderr, "Finished loop, len = %zu\n", len);
	if (ferror(stdin))
		die("Error reading input.\n");
	if (!len) {
		die("Input truncated.\n");
	} else if (len == 16) {
		if (crypto_unlock(
			buf + 16, shared_secret, ctr, buf, buf + 16, 0)
		) {
			die("Decryption failed.\n");
		}
	} else {
		len -= 16;
		if (crypto_unlock(
			buf, shared_secret, ctr, buf + len, buf, len)
		) {
			die("Decryption failed.\n");
		}
		if (fwrite(buf, len, 1, stdout) != 1)
			die("Write error.\n");
		nonce_inc(ctr);
	}
	return 0;
}
