#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <monocypher.h>

#include "common.h"

#ifndef PWDTTY
#define PWDTTY "/dev/tty"
#endif

static
void
decrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile)
{
	uint8_t buf[BLOCKSIZE + 16];
	uint8_t ctr[24] = {0};
	size_t len;

	while ((len = fread(buf, 1, BLOCKSIZE + 16, stdin)) == BLOCKSIZE + 16) {
		if (crypto_unlock(
			buf, key, ctr, buf + BLOCKSIZE, buf, BLOCKSIZE)
		) {
			die("Decryption failed");
		}
		if (fwrite(buf, BLOCKSIZE, 1, stdout) != 1)
			die("Write error");
		nonce_inc(ctr);
	}
	if (ferror(stdin))
		die("Error reading input");
	if (!len) {
		die("Input truncated");
	} else if (len == 16) {
		if (crypto_unlock(
			buf + 16, key, ctr, buf, buf + 16, 0)
		) {
			die("Decryption failed");
		}
	} else {
		len -= 16;
		if (crypto_unlock(
			buf, key, ctr, buf + len, buf, len)
		) {
			die("Decryption failed");
		}
		if (fwrite(buf, len, 1, stdout) != 1)
			die("Write error");
		nonce_inc(ctr);
	}
}

int
main(void)
{
	uint8_t public_key[32];
	uint8_t secret_key[32];
	uint8_t password[1024] = "test";
	uint32_t password_len = 4;

	uint8_t hidden[32];
	uint8_t eph_public_key[32];
	uint8_t shared[32];

	password_len = read_password(password, sizeof(password), PWDTTY);
	key_derive(secret_key, password, password_len);
	crypto_wipe(password, sizeof(password));
	password_len = 0;
	crypto_x25519_public_key(public_key, secret_key);

	if (fread(hidden, sizeof(hidden), 1, stdin) != 1)
		die("Read error");
	crypto_hidden_to_curve(eph_public_key, hidden);
	show_fingerprint(eph_public_key);

	key_exchange(shared, eph_public_key, public_key, secret_key);
	crypto_wipe(secret_key, sizeof(secret_key));

	decrypt_blocks(shared, stdin, stdout);
	return 0;
}
