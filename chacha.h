#ifndef KEYGENME_CHACHA_H
#define KEYGENME_CHACHA_H

#include <stdint.h>

#define CHACHA_KEY_BYTES	32
#define CHACHA_NONCE_BYTES	12
#define CHACHA_BLOCK_BYTES	64
#define CHACHA_BLOCK_WORDS	(64/4)

void chacha_block(void *out, const void *key, const void *nonce, uint32_t block_count);

#endif

