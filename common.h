#define die(...) do { \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, "\n"); \
		exit(1); \
	} while(0)

#define BLOCKSIZE (64 * 1024)

void key_derive(uint8_t k[32], const uint8_t *buf, uint32_t bufsize);
void key_exchange(uint8_t shared[32], const uint8_t other[32], const uint8_t public[32], const uint8_t secret[32]);
void show_fingerprint(const uint8_t public[32]);

void nonce_inc(uint8_t nonce[24]);
uint32_t read_password(uint8_t *buf, uint32_t bufsize, const char *ttypath);
