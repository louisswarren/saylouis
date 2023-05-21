#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/random.h>
#include <termios.h>

#include <termios.h>

#include <monocypher.h>

#include "unified.h"
#include "utils.h"

int
main(int argc, char *argv[])
{
	uint8_t public_key[32];
	uint8_t password[1024];
	uint32_t password_len = 0;

	FILE *tty;

	if (argc == 2 && argv[1][0] == '-' && argv[1][1] == 'b') {
		password_len = 32;
		memset(password, 'x', password_len);
		derive_key_pair(public_key, NULL, password, password_len);
		return 0;
	}

	if (!(tty = fopen("/dev/tty", "r+")))
		die("Failed to get a password");

	password_len = read_password((char *)password, sizeof(password), tty);
	fclose(tty);

	if (!password_len)
		die("Password was empty");
	if (password_len + 1 == sizeof(password))
		die("Password was truncated");

	derive_key_pair(public_key, NULL, password, password_len);
	crypto_wipe(password, sizeof(password));
	password_len = 0;

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
