#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <monocypher.h>

#include "common.h"

#ifndef PWDTTY
#define PWDTTY "/dev/tty"
#endif

int
main(void)
{
	uint8_t public_key[32];
	uint8_t secret_key[32];
	uint8_t password[1024];
	uint32_t password_len = 0;

	FILE *tty = fopen(PWDTTY, "r+");
	if (!tty)
		die("Failed to get a password from %s", PWDTTY);

	password_len = read_password(password, sizeof(password), tty);
	key_derive(secret_key, password, password_len);
	crypto_wipe(password, sizeof(password));
	password_len = 0;

	crypto_x25519_public_key(public_key, secret_key);
	crypto_wipe(secret_key, sizeof(secret_key));

	printf(
		"static const uint8_t my_public_key"
		"[%zu] = {\n",
		sizeof(public_key)
	);
	for (unsigned int i = 0; i < sizeof(public_key); ++i) {
		if (i % 8 == 0)
			printf("\t");
		printf("0x%02x", public_key[i]);
		if (i + 1 == sizeof(public_key))
			printf("\n");
		else if (i % 8 == 7)
			printf(",\n");
		else
			printf(", ");
	}
	printf("};\n");

	return 0;
}
