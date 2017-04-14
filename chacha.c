/*
 * chacha.c: Provide a simple implementation of the ChaCha20 block function.
 *
 * Implemented as described on https://tools.ietf.org/html/rfc7539.
 */

#include <stdint.h>
#include <string.h>

#include "chacha.h"

struct ChaChaContext {
	uint32_t state[16];
};

static inline uint32_t
rotl(uint32_t i, size_t bits)
{
	return ((i << bits) | (i >> (32 - bits)));
}

static void
chacha_quarter_round(struct ChaChaContext *ctx,
		uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	uint32_t *s = ctx->state;

	s[d] = rotl(((s[a] += s[b]) ^ s[d]), 16);
	s[b] = rotl(((s[c] += s[d]) ^ s[b]), 12);
	s[d] = rotl(((s[a] += s[b]) ^ s[d]), 8);
	s[b] = rotl(((s[c] += s[d]) ^ s[b]), 7);
}

void
chacha_block(void *out, const void *key, const void *nonce, uint32_t block_count)
{
	struct ChaChaContext ctx = {
		{
			// Constants
			0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
		}
	};
	struct ChaChaContext working;
	const unsigned char *keyb = key;
	const unsigned char *nonceb = nonce;
	unsigned char *outb = out;

	for (size_t i = 0; i < 256/8; i += 4) {
		ctx.state[4 + i/4] = (keyb[i + 3] << 24)
			| (keyb[i + 2] << 16)
			| (keyb[i + 1] <<  8)
			|  keyb[i];
	}

	ctx.state[12] = block_count;

	for (size_t i = 0; i < 96/8; i += 4) {
		ctx.state[13 + i/4] = (nonceb[i + 3] << 24)
			| (nonceb[i + 2] << 16)
			| (nonceb[i + 1] <<  8)
			|  nonceb[i];
	}

	working = ctx;

	for (size_t i = 0; i < 10; ++i) {
		chacha_quarter_round(&working, 0, 4,  8, 12);
		chacha_quarter_round(&working, 1, 5,  9, 13);
		chacha_quarter_round(&working, 2, 6, 10, 14);
		chacha_quarter_round(&working, 3, 7, 11, 15);
		chacha_quarter_round(&working, 0, 5, 10, 15);
		chacha_quarter_round(&working, 1, 6, 11, 12);
		chacha_quarter_round(&working, 2, 7,  8, 13);
		chacha_quarter_round(&working, 3, 4,  9, 14);
	}

	for (size_t i = 0; i < sizeof(ctx.state)/sizeof(*ctx.state); ++i) {
		ctx.state[i] += working.state[i];

		outb[4 * i + 3] = (ctx.state[i] & 0xFF000000) >> 24;
		outb[4 * i + 2] = (ctx.state[i] & 0x00FF0000) >> 16;
		outb[4 * i + 1] = (ctx.state[i] & 0x0000FF00) >>  8;
		outb[4 * i]     = (ctx.state[i] & 0x000000FF);
	}
}

