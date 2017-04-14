#ifndef KEYGENME_BASE32_H
#define KEYGENME_BASE32_H

void base32_encode_serial(char *code, unsigned __int128 serial);

int base32_decode_serial(unsigned __int128 *serial, const char *code);

#endif

