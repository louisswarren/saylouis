#define die(...) do { \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
		exit(1); \
	} while(0)

static
int
tty_set_no_echo(struct termios *tmp, int fd)
{
	struct termios term_noecho;
	if (tcgetattr(fd, tmp))
		return -1;
	term_noecho = *tmp;
	term_noecho.c_lflag &= (tcflag_t)~ECHO;
	return tcsetattr(fd, TCSAFLUSH, &term_noecho);
}

static
int
tty_unset_no_echo(const struct termios *tmp, int fd)
{
	return tcsetattr(fd, TCSAFLUSH, tmp);
}

/* Read a string with length at most bufsize-1 from tty into buf */
static
uint32_t
read_password(uint8_t *buf, uint32_t bufsize, FILE *tty)
{
	uint32_t password_len;
	struct termios tmp;

	if (tty_set_no_echo(&tmp, tty->_fileno)) {
		buf = fgets(buf, (int)bufsize, tty);
	} else {
		fprintf(tty, "Passphrase (Echo off): ");
		fflush(tty);
		buf = fgets(buf, (int)bufsize, tty);
		fprintf(tty, "\n");
		(void)tty_unset_no_echo(&tmp, tty->_fileno);
	}

	if (!buf)
		return 0;

	password_len = (uint32_t)strlen(buf);

	if (password_len && buf[password_len - 1] == '\n')
		buf[--password_len] = '\0';

	return password_len;
}
