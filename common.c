#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include "common.h"

static
int
set_no_echo(struct termios *prev)
{
	struct termios term_noecho;
	if (tcgetattr(0, prev))
		return 1;
	term_noecho = *prev;
	term_noecho.c_lflag &= (tcflag_t)~ECHO;
	if (tcsetattr(0, TCSAFLUSH, &term_noecho))
		return 1;
	return 0;
}

uint32_t
read_password(uint8_t *buf, uint32_t bufsize, const char *ttypath)
{
	uint32_t password_len = 0;
	struct termios term_old;
	FILE *tty = fopen(ttypath, "r");

	if (!tty)
		die("Failed to get a password from %s\n", ttypath);

	if (set_no_echo(&term_old)) {
		buf = fgets(buf, (int)bufsize, tty);
	} else {
		fprintf(stderr, "Passphrase (Echo off): ");
		buf = fgets(buf, (int)bufsize, tty);
		(void)tcsetattr(0, TCSAFLUSH, &term_old);
	}
	fclose(tty);

	if (!buf)
		die("Failed to read password.\n");

	password_len = (uint32_t)strlen(buf);

	if (password_len + 1 == bufsize)
		die("Password was truncated.\n");

	if (password_len && buf[password_len - 1] == '\n')
		buf[password_len-- - 1] = '\0';

	if (!password_len)
		die("Password was empty.\n");

	return password_len;
}
