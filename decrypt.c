#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <monocypher.h>

#include "common.h"

#ifndef PWDTTY
#define PWDTTY "/dev/tty"
#endif

#define BLOCKSIZE 20

int
main(void)
{
	uint8_t public_key[32];
	uint8_t secret_key[32];
	uint8_t password[1024] = "test";
	uint32_t password_len = 4;

	uint8_t hidden[32];
	uint8_t eph_public_key[32];
	uint8_t shared_secret[32];
	crypto_blake2b_ctx blake_ctx;

	uint8_t buf[BLOCKSIZE + 16];
	uint8_t ctr[24] = {0};
	size_t len;

	password_len = read_password(password, sizeof(password), PWDTTY);
	key_derive(secret_key, password, password_len);
	crypto_wipe(password, sizeof(password));
	crypto_x25519_public_key(public_key, secret_key);

	if (fread(hidden, sizeof(hidden), 1, stdin) != 1)
		die("Read error.\n");
	crypto_hidden_to_curve(eph_public_key, hidden);
	show_fingerprint(eph_public_key);

	key_exchange(shared_secret, eph_public_key, public_key, secret_key);
	crypto_wipe(secret_key, sizeof(secret_key));

	while ((len = fread(buf, 1, BLOCKSIZE + 16, stdin)) == BLOCKSIZE + 16) {
		if (crypto_unlock(
			buf, shared_secret, ctr, buf + BLOCKSIZE, buf, BLOCKSIZE)
		) {
			die("Decryption failed.\n");
		}
		if (fwrite(buf, BLOCKSIZE, 1, stdout) != 1)
			die("Write error.\n");
		nonce_inc(ctr);
	}
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
