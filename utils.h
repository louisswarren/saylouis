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
