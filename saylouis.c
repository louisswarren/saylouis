#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/random.h>
#include <termios.h>

#include <termios.h>

#include <monocypher.h>

#include "unified.h"
#include "utils.h"

#include "my_public_key.h"

#ifndef PWDTTY
#define PWDTTY "/dev/tty"
#endif

static
void
show_fingerprint(const uint8_t public[32])
{
	for (int i = 0; i < 32; ++i)
		fprintf(stderr, "%x", public[i]);
	fprintf(stderr, "\n");
}

static
int
decrypt(void)
{
	uint8_t public_key[32];
	uint8_t secret_key[32];
	uint8_t password[1024];
	uint32_t password_len;

	uint8_t hidden[32];
	uint8_t eph_public_key[32];
	uint8_t shared[32];

	if (fread(hidden, sizeof(hidden), 1, stdin) != 1)
		die("Read error");

	fprintf(stderr, "Decrypting from public key: ");
	unhide_key(eph_public_key, hidden);
	show_fingerprint(eph_public_key);
	fflush(stderr);

	FILE *tty = fopen(PWDTTY, "r+");
	if (!tty)
		die("Failed to get a password from %s", PWDTTY);

	password_len = read_password(password, sizeof(password), tty);
	fclose(tty);

	if (!password_len)
		die("Password was empty");
	if (password_len + 1 == sizeof(password))
		die("Password was truncated");

	derive_key_pair(public_key, secret_key, password, password_len);
	crypto_wipe(password, sizeof(password));
	password_len = 0;
	key_from_secret(shared, hidden, secret_key);

	decrypt_blocks(shared, stdin, stdout);
	return 0;
}

static
int
gen_public_key(void)
{
	uint8_t public_key[32];
	uint8_t password[1024];
	uint32_t password_len = 0;

	FILE *tty = fopen(PWDTTY, "r+");
	if (!tty)
		die("Failed to get a password from %s", PWDTTY);

	password_len = read_password(password, sizeof(password), tty);
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

static
int
saylouis(void)
{
	uint8_t seed[32];
	uint8_t hidden[32];
	uint8_t public[32];
	uint8_t shared[32];

	/* Get a new key pair from a random seed */
	if (getrandom(seed, sizeof(seed), 0) != sizeof(seed))
		die("Failed to seed a new key");


	key_from_random(shared, hidden, seed, my_public_key);

	fprintf(stderr, "Encrypting with public key: ");
	unhide_key(public, hidden);
	show_fingerprint(public);
	fflush(stderr);

	/* Output the hidden public key */
	if (fwrite(hidden, sizeof(hidden), 1, stdout) != 1)
		die("Write error");

	encrypt_blocks(shared, stdin, stdout);
	crypto_wipe(shared, sizeof(shared));

	return 0;
}

int
main(int argc, char *argv[])
{
	if (argc == 1)
		return saylouis();
	if (argc == 2 && !strcmp(argv[1], "-d"))
		return decrypt();
	die("Usage: %s < plaintext > ciphertext", argv[0]);
}
