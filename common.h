#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while(0)

uint32_t read_password(uint8_t *buf, uint32_t bufsize, const char *ttypath);
