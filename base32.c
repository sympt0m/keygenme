/*
 * base32.c: Base32 encoding for 125-bit data in a __int128.
 *
 * Implemented as described in https://tools.ietf.org/html/rfc4648.
 */

#include <stddef.h>

#include "base32.h"

static const char *b32alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void
base32_encode_serial(char *code, unsigned __int128 serial)
{
	/*
	 * 6. Shift XDABC left by 3 bits so that DABC are aligned with the
	 *    base32 boundary.
	 * 7. Encode XDABC in unpadded uppercase base32, big endian.
	 *
	 * We have 25 characters. One character in base32 can represent 5 bits,
	 * so that we can encode 125 bits.
	 */
	unsigned int bits;
	unsigned int written = 0;

	serial <<= 3;

	for (size_t i = 0; i < 125/5; ++i) {
		bits = (serial >> (128 - 5));
		serial <<= 5;
		*code++ = b32alphabet[bits];

		/*
		 * 8. Insert dashes after every fifth character.
		 */
		if (++written == 5) {
			*code++ = '-';
			written = 0;
		}
	}

	*--code = '\0';
}

int
base32_decode_serial(unsigned __int128 *serial, const char *code)
{
	unsigned char c;
	unsigned int bits;
	unsigned __int128 s = 0;

	for (; *code != '\0'; ++code) {
		c = *(const unsigned char *)code;
		if (c == '-')
			continue;

		if (c >= 'A' && c <= 'Z')
			bits = c - 'A';
		else if (c >= '2' && c <= '7')
			bits = (c - '2') + 26;
		else
			return -1;

		s <<= 5;
		s |= bits;
	}

	*serial = s;

	return 0;
}

