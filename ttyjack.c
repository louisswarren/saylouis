#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

FILE *
fopen(const char *restrict pathname, const char *restrict mode)
{
	const char tty_path[] = "/dev/tty";
	const char pwd_path[] = "./pwdtty";

	FILE *(*stdio_fopen)(const char *restrict, const char *restrict);
	stdio_fopen = dlsym(RTLD_NEXT, "fopen");

	if (!strcmp(pathname, tty_path)) {
		fprintf(stderr, "Redirecting %s to %s\n", tty_path, pwd_path);
		pathname = pwd_path;
	}
	return stdio_fopen(pathname, mode);
}
