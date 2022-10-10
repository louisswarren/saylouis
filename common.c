#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <monocypher.h>

#include "common.h"

void key_derive(uint8_t key[32], const uint8_t *buf, uint32_t buflen)
{
	const uint32_t kdf_blocks = 512 * 1024;
	const uint32_t kdf_iterations = 3;
	const uint8_t kdf_salt[16] = {
		'l', 'o', 'u', 'i',
		's', '@', 'l', 's',
		'w', '.', 'n', 'z',
		31,  41,  59,  26,
	};

	void *work_area = calloc(kdf_blocks, 1024);
	if (!work_area)
		die("Failed to allocate work area");

	crypto_argon2i(
		key, 32,
		work_area,
		kdf_blocks, kdf_iterations,
		buf, buflen,
		kdf_salt, sizeof(kdf_salt)
	);
}

void shared_secret_key_commit(
	uint8_t shared[32],
	const uint8_t louis_public[32],
	const uint8_t ephemeral_public[32]
) {
	crypto_blake2b_ctx bc;
	crypto_blake2b_general_init(&bc, 32, NULL, 0);
	crypto_blake2b_update(&bc, shared, 32);
	crypto_blake2b_update(&bc, louis_public, 32);
	crypto_blake2b_update(&bc, ephemeral_public, 32);
	crypto_blake2b_final(&bc, shared);
}

void
nonce_inc(uint8_t nonce[24])
{
	for (int i = 0; i < 24 && ++nonce[i] == 0; ++i);
}

void
show_fingerprint(const uint8_t public[32])
{
	for (int i = 0; i < 32; ++i)
		fprintf(stderr, "%x", public[i]);
	fprintf(stderr, "\n");
}

static
int
tty_set_no_echo(struct termios *tmp, int fd)
{
	struct termios term_noecho;
	if (tcgetattr(fd, tmp))
		return -1;
	term_noecho = *tmp;
	term_noecho.c_lflag &= (tcflag_t)~ECHO;
	if (tcsetattr(fd, TCSAFLUSH, &term_noecho))
		return -1;
	return 0;
}

static
void
tty_unset_no_echo(struct termios *tmp, int fd)
{
	(void)tcsetattr(fd, TCSAFLUSH, tmp);
}

uint32_t
read_password(uint8_t *buf, uint32_t bufsize, FILE *tty)
{
	uint32_t password_len = 0;
	struct termios tmp;

	if (tty_set_no_echo(&tmp, tty->_fileno)) {
		buf = fgets(buf, (int)bufsize, tty);
	} else {
		fprintf(tty, "Passphrase (Echo off): ");
		fflush(tty);
		buf = fgets(buf, (int)bufsize, tty);
		fprintf(tty, "\n");
		tty_unset_no_echo(&tmp, tty->_fileno);
	}
	fclose(tty);

	if (!buf)
		die("Failed to read password");

	password_len = (uint32_t)strlen(buf);

	if (password_len + 1 == bufsize)
		die("Password was truncated");

	if (password_len && buf[password_len - 1] == '\n')
		buf[password_len-- - 1] = '\0';

	if (!password_len)
		die("Password was empty");

	return password_len;
}
