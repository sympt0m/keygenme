/*
 * validkey.c: check if a given key is valid.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base32.h"
#include "bin.h"
#include "chacha.h"
#include "blake2.h"
#include "tweetnacl.h"

static inline bool
digitsdivisiblebyseven(uint32_t a)
{
	unsigned int sum = 0;

	while (a != 0) {
		sum += (a % 10);
		a /= 10;
	}

	return (sum % 7 == 0);
}

static inline bool
verifybasekey(uint32_t a, uint32_t b, uint32_t c)
{
	unsigned char digest[crypto_hash_sha512_BYTES];
	uint32_t block[CHACHA_BLOCK_WORDS];
	unsigned char *key = digest;
	const unsigned char *nonce = nonce_der
		+ nonce_der_size
		- CHACHA_NONCE_BYTES;
	bool ret = true;

	(void)crypto_hash_sha512_tweet(digest, (unsigned char *)&a, sizeof(a));

	chacha_block(block, key, nonce, 0);

	ret &= (b == block[0]);
	ret &= (c == block[1]);

	memset(block, 0, sizeof(block));
	memset(digest, 0, sizeof(digest));

	return ret;
}

static bool
verifychecksum(const uint32_t *abc, uint8_t *d)
{
	uint8_t myd[3];
	bool ret = true;

	blake2b(myd, abc, baitkey + 389, 3, sizeof(*abc) * 3, BLAKE2B_KEYBYTES);

	ret &= (myd[0] == d[0]);
	ret &= (myd[1] == d[1]);
	ret &= (myd[2] == d[2]);

	return ret;
}

static void
exitondebug(void)
{
	struct timespec req, rem;
	struct timespec old, new;
	long long tdelta;

	req.tv_sec = 1;
	req.tv_nsec = 0;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &old) != 0)
		exit(EXIT_FAILURE);

	if (nanosleep(&req, &rem) != 0)
		exit(EXIT_FAILURE);

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &new) != 0)
		exit(EXIT_FAILURE);

	tdelta = new.tv_sec - old.tv_sec;

	/* Check this early for overflow chance */
	if (tdelta > 1)
		exit(EXIT_FAILURE);

	tdelta *= 1000000000;
	tdelta += new.tv_nsec - old.tv_nsec;

	/* Difference too large: debugger present (nanosleep guarantees sleeping
	 *   for at *least* as long as requested);
	 * difference too small: anti-anti-debugger present
	 */
	if (tdelta > 2000000000 || tdelta < 1000000000)
		exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	/* AAAAA-BBBBB-CCCCC-DDDDD-EEEEE \0 */
	char *code;
	size_t codelen;
	unsigned __int128 serial;
	uint32_t abc[3];
	uint32_t *a = &abc[0];
	uint32_t *b = &abc[1];
	uint32_t *c = &abc[2];
	uint8_t d[3];

	if (argc < 2) {
		fprintf(stderr, "Usage: %s key\n"
				"Returns %d if key is valid, %d otherwise.\n",
				argv[0], EXIT_SUCCESS, EXIT_FAILURE);
		return EXIT_FAILURE;
	}

	/*
	 * 0. Prevent presence of debugger.
	 */
	exitondebug();

	code = argv[1];
	codelen = strlen(code);

	/*
	 * 1. Verify that the string is 29 characters long and contains dashes
	 *    every five characters.
	 */
	if (codelen != 29
			|| code[5] != '-'
			|| code[11] != '-'
			|| code[17] != '-'
			|| code[23] != '-')
		return EXIT_FAILURE;

	/* 
	 * 2. Decode (special) base32 where - is tossed. Error out on invalid
	 *    base32.
	 * 3. Shift XDABC right by 3 bits.
	 */
	if (base32_decode_serial(&serial, code) != 0)
		return EXIT_FAILURE;

	for (size_t i = 0; i < sizeof(abc)/sizeof(*abc); ++i) {
		abc[sizeof(abc)/sizeof(*abc) - i - 1] = (uint32_t)(serial & 0xFFFFFFFF);
		serial >>= 32;
	}
	for (size_t i = 0; i < sizeof(d)/sizeof(*d); ++i) {
		d[sizeof(d)/sizeof(*d) - i - 1] = (uint8_t)(serial & 0xFF);
		serial >>= 8;
	}

	/*
	 * 4. Verify that the sum of the base10 digits in A modulo 7 == 0.
	 */
	if (!digitsdivisiblebyseven(*a))
		return EXIT_FAILURE;

	/*
	 * 5. Build ChaCha20 state with key = sha512(A) and nonce = some constant.
	 * 6. Run ChaCha20 block function and unserialize the first two u32s.
	 *    Check that they match B and C.
	 */
	if (!verifybasekey(*a, *b, *c))
		return EXIT_FAILURE;

	/*
	 * 7. Generate checksum D using BLAKE2b(key=some other constant,
	 *    A || B || C, len=3) and verify equality.
	 */
	if (!verifychecksum(abc, d))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

