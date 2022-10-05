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
	uint8_t password[1024];
	uint32_t password_len = 0;

	if (!(work_area = calloc(nb_blocks, 1024)))
		die("Failed to allocate work area.\n");

	password_len = read_password(password, sizeof(password), PWDTTY);

	crypto_argon2i(
		secret_key, sizeof(secret_key),
		work_area,
		nb_blocks, nb_iterations,
		password, password_len,
		salt, sizeof(salt)
	);
	crypto_wipe(password, sizeof(password));

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
