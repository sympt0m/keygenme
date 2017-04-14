# External Perspective

This section details the design and the design process for external readers.
My original notes are further down below.

Terms (*these may not be industry-standard*):

* **seed**: The seed is a variable value that can be randomized. A keygen will
  generate a random seed and then apply the required algorithms over it,
  deriving the necessary values from it directly or indirectly.
* **serial**: The full data that is the result of a key generation and that can
  be validated, before encoding (i.e. in binary).
* **key**: The encoded serial in human-readable form.

## Choice of Algorithms

My initial design involved ChaCha20, for which I already had a partial
implementation based based on the description in
[RFC 7539](https://tools.ietf.org/html/rfc7539). That was my main reason to
choose it.

I then figured I need some kind of checksum as well, and originally picked
Ed25519. The checksum was meant to be a single byte, so that brute-forcing the
result is possible, rather than trying to figure out where a private key is. A
remnant of that are the bin/pk.bin and bin/sk.bin, which were meant to be a
Ed25519 public key and private key, respectively.

However, it turns out, Ed25519 signatures didn't work the way I thought they
did, so that `validkey` couldn't actually compute and then truncate the
checksum.

I thus changed my checksum to be as many bytes of [BLAKE2b](https://blake2.net/)
as possible instead.

Initially, I wanted to use [TweetNaCl](https://tweetnacl.cr.yp.to/) for
everything. As it turns out, the Ed25519 part didn't go as planned and I needed
deeper access to ChaCha20, so that the only part left was the hashing, which is
SHA-512.

As an added layer, I was intending to use RC4, but decided against it, given the
existing difficulty.

Encoding the binary data we have to a human-readable format more or less
prompted either base16 (hex), Base32 or base64. Striking a balance between
simplicity, human-readability and efficiency, I chose Base32 as described in
[RFC 4648](https://tools.ietf.org/html/rfc4648) sec. 4.

I've intentionally only picked algorithms that are either widely known (part of
TLS or the Python stdandard library) so that the constants can be searched and
the respective algorithm found without too much hassle.

So we have:

Algorithm | Parameters
----------|---------
ChaCha20  | nonce (96 bit), key (256 bit), plaintext (optional)
BLAKE2b   | key (up to 512 bit; optional), length (up to 512 bit), message
SHA-512   | message
Base32    | message

## Putting Everything Together

A keygen always needs a randomizable element. I call this the "seed". In
production, this may be a monotonically incrementing serial number or other
things. In this case, I chose the "seed" (referred to as `A` in my notes) to be
an unsigned 32-bit integer. This was mainly to align with the natural
boundaries of the internal state for ChaCha20. I decided that the sum of the
seed's digits in base 10 should be divisible by 7, which is a nod to certain
version(s?) of Windows.

Then there's the question of how much data I can even use. Looking back at what
Windows XP used, a key there was formed like ABCDE-FGHIJ-KLMNO-PQRST-UWXYZ, so I
had 25 characters available. Base32 encodes five bits per character, so I had
125 bits available to me. Rounded down to the nearest octet, that is 15 bytes.
Four bytes are gone for `A` already, leaving me with 11 more bytes to fill.

As a first step, the seed `A` gets "expanded" into `B` and `C`. This is
accomplished by creating a ChaCha20 state and running the ChaCha block function
(RFC 7539 sec. 2.3) once. `B` and `C` are the new state's first and second
words, respectively.

Twelve bytes are gone, three more to fill. Originally, this was meant to be a
one-byte truncated Ed25519 signature, meant to be brute-forced, but dealing with
truncated signatures ended up being a pain and I didn't feel like rewriting the
Ed25519 wheel and learning too much about it. Thus, I just picked BLAKE2b for
its flexibility with output, generating digest `D` over `A`, `B` and `C`.
All 15 bytes are now in use.

Internally, I use a `__int128` to represent this data, meaning I have three
leftover bits. I just ended up making the first byte random and then just shift
them out in the process of creating the full serial.

## Choosing Parameters

Several of the chosen algorithms require parameters.

ChaCha20 requires a 96-bit nonce and a 256-bit key. Since we use this for
deriving `B` and `C` from `A`, I figured I might just expand A using whatever
hash function comes with TweetNaCl, which ended up being SHA-512, and use the
digest for the key; this ends up being SHA-512/256. The nonce is part of a DER
that describes NIST P-256 EC params generated with `openssl ecparam`. This was
meant to be a red herring.

BLAKE2b can take an optional key. I made it take 64 bytes (the maximum) from the
middle of an RSA private key, which was also put there as a red herring. The
output digest length of 3 was necessary by design.

## Compilation

Since I used `__int128`, which is both (1) non-standard, and (2) only supported
by gcc and clang on 64-bit platforms, I could only compile it for 64-bit
platforms.

`-fPIC` is apparently effectively implied anyway on 64-bit platforms.
Originally, I added `-funroll-loops`, but it ended up making the already
surprisingly complex output even larger, so I remove that part again. `-O0` was
set to try and prevent the compiler from mangling the functions' semantics as
much as possible.

Afterwards, `strip -s` is used to remove symbols as neatly as possible.

## Anti-Debugging

The only anti-debugging measure taken was adapted from
[Gozi](https://www.govcert.admin.ch/blog/30/when-gozi-lost-its-head), which is a
check that a `nanosleep` sleeps neither too short nor way too long, to avoid
simple anti-anti debugging and preventing debugging with no precautions taken.

# Original Notes

These are the notes I originally used during development.

## Key Generation

1. Generate a random u32 A. Ensure the sum of the digits if converted to base 10
   modulo 7 == 0.
2. Build ChaCha20 state with key = sha512(A) [we need this to be brute 
   forceable] and nonce = some constant (ideally misleading, like a RSA pubkey
   or ECDSA pubkey in PEM).
3. Run ChaCha20 block function and unserialize the first two u32s for B and C.
4. Generate checksum D using BLAKE2b(key=some other constant, A || B || C,
   len=3).
5. Generate XDABC: A, B, C and D, plus padding with random byte X.
6. Shift XDABC left by 3 bits so that DABC are aligned with the Base32 boundary.
7. Encode unpadded XDABC in uppercase Base32, big endian.
8. Insert dashes after every fifth character.
9. Output.

    0123456789abcdef0123456789abcdef
    XXDDDDDDAAAAAAAABBBBBBBBCCCCCCCC

## Key Validation

1. Verify that the string is 29 characters long and contains dashes every five
   characters.
2. Decode (special) Base32 where - is tossed. Error out on invalid Base32.
3. Shift XDABC right by 3 bits.
4. Verify that the sum of the base10 digits in A modulo 7 == 0.
5. Build ChaCha20 state with key = sha512(A) and nonce = some constant.
6. Run ChaCha20 block function and unserialize the first two u32s. Check that
   they match B and C.
7. Generate checksum D using BLAKE2b(key=some other constant, A || B || C,
   len=3) and verify equality.

