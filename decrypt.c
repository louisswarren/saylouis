#include <stdio.h>
#include <stdlib.h>

#include <monocypher.h>

#include "common.h"

#ifndef PWDTTY
#define PWDTTY "/dev/tty"
#endif

static
void
decrypt_blocks(const uint8_t key[32], FILE *infile, FILE *outfile)
{
	uint8_t *buf;
	uint8_t ctr[24] = {0};
	size_t len;

	if (!(buf = malloc(BLOCKSIZE + 16)))
		die("Out of memory");

	while ((len = fread(buf, 1, BLOCKSIZE + 16, infile)) == BLOCKSIZE + 16) {
		if (crypto_unlock(
			buf, key, ctr, buf + BLOCKSIZE, buf, BLOCKSIZE)
		) {
			die("Decryption failed");
		}
		if (fwrite(buf, BLOCKSIZE, 1, outfile) != 1)
			die("Write error");
		nonce_inc(ctr);
	}
	if (ferror(infile))
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
		if (fwrite(buf, len, 1, outfile) != 1)
			die("Write error");
		nonce_inc(ctr);
	}
	crypto_wipe(buf, BLOCKSIZE + 16);
	free(buf);
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

	FILE *tty = fopen(PWDTTY, "r+");
	if (!tty)
		die("Failed to get a password from %s", PWDTTY);

	password_len = read_password(password, sizeof(password), tty);
	key_derive(secret_key, password, password_len);
	crypto_wipe(password, sizeof(password));
	password_len = 0;
	crypto_x25519_public_key(public_key, secret_key);

	if (fread(hidden, sizeof(hidden), 1, stdin) != 1)
		die("Read error");
	crypto_hidden_to_curve(eph_public_key, hidden);
	show_fingerprint(eph_public_key);

	crypto_x25519(shared, secret_key, eph_public_key);
	shared_secret_key_commit(shared, public_key, eph_public_key);
	crypto_wipe(secret_key, sizeof(secret_key));

	decrypt_blocks(shared, stdin, stdout);
	return 0;
}
