/*
 * genkey.c: Generate a new key.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base32.h"
#include "bin.h"
#include "chacha.h"
#include "blake2.h"
#include "randombytes.h"
#include "tweetnacl.h"

static bool
digitsdivisiblebyseven(uint32_t a)
{
	unsigned int sum = 0;

	while (a != 0) {
		sum += (a % 10);
		a /= 10;
	}

	return (sum % 7 == 0);
}

static void
makebasekey(uint32_t a, uint32_t *b, uint32_t *c)
{
	/*
	 * 2. Build ChaCha20 state with key = sha512(A) (we need this to be
	 *    brute forceable) and nonce = some constant (ideally misleading,
	 *    like a RSA pubkey or ECDSA pubkey in PEM).
	 * 3. Run ChaCha20 block function and unserialize the first two u32s
	 *    for B and C.
	 */
	unsigned char digest[crypto_hash_sha512_BYTES];
	uint32_t block[CHACHA_BLOCK_WORDS];
	unsigned char *key = digest;
	const unsigned char *nonce = nonce_der
		+ nonce_der_size
		- CHACHA_NONCE_BYTES;

	(void)crypto_hash_sha512_tweet(digest, (unsigned char *)&a, sizeof(a));

	chacha_block(block, key, nonce, 0);

	*b = block[0];
	*c = block[1];

	memset(block, 0, sizeof(block));
}

static void
checksumbasekey(const uint32_t *abc, uint8_t *d)
{
	/* 
	 * 4. Generate checksum D using BLAKE2b(key=some other constant,
	 *    A || B || C, len=3).
	 */
	blake2b(d, abc, baitkey + 389, 3, sizeof(*abc) * 3, BLAKE2B_KEYBYTES);
}

int
main(void)
{
	uint32_t abc[3];
	uint32_t *a = &abc[0];
	uint32_t *b = &abc[1];
	uint32_t *c = &abc[2];
	uint8_t d[3];
	unsigned __int128 serial = 0;
	/* AAAAA-BBBBB-CCCCC-DDDDD-EEEEE \0 */
	char code[25 + 4 + 1];

	/*
	 * 1. Generate a random u32 A. Ensure the sum of the digits if converted
	 *    to base 10 modulo 7 == 0 (NT 4.0 algorithm).
	 */
	do {
		randombytes(a, sizeof(*a));
	} while (!digitsdivisiblebyseven(*a));

	makebasekey(*a, b, c);
	checksumbasekey(abc, d);

	/*
	 * 5. Generate XDABC: A, B, C and D, plus padding with random byte X.
	 */
	randombytes(&serial, 1);
	for (size_t i = 0; i < sizeof(d)/sizeof(*d); ++i) {
		serial <<= 8;
		serial |= d[i];
	}

	for (size_t i = 0; i < sizeof(abc)/sizeof(*abc); ++i) {
		serial <<= 32;
		serial |= abc[i];
	}

	base32_encode_serial(code, serial);

	/*
	 * 9. Output.
	 */
	printf("%s (A: %08x, B: %08x, C: %08x, D: %02x%02x%02x)\n",
			code, *a, *b, *c, d[0], d[1], d[2]);

	return EXIT_SUCCESS;
}

