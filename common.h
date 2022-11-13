#define BLOCKSIZE (64 * 1024 * 1024)

void show_fingerprint(const uint8_t public[32]);

void nonce_inc(uint8_t nonce[24]);
uint32_t read_password(uint8_t *buf, uint32_t bufsize, FILE *tty);
