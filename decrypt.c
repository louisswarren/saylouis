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
	derive_key_pair(public_key, secret_key, password, password_len);
	crypto_wipe(password, sizeof(password));
	password_len = 0;
	key_from_secret(shared, hidden, secret_key);

	decrypt_blocks(shared, stdin, stdout);
	return 0;
}
