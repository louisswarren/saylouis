#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <monocypher.h>

#include "unified.h"
#define die(...) do { \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
		exit(1); \
	} while(0)

#ifndef PWDTTY
#define PWDTTY "/dev/tty"
#endif

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

static
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

int
main(void)
{
	uint8_t public_key[32];
	uint8_t password[1024];
	uint32_t password_len = 0;

	FILE *tty = fopen(PWDTTY, "r+");
	if (!tty)
		die("Failed to get a password from %s", PWDTTY);

	password_len = read_password(password, sizeof(password), tty);

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
