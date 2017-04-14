include config.mk

.PHONY: clean strip

CFLAGS += -D_BSD_SOURCE -D_POSIX_C_SOURCE=200809L

all: genkey validkey

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

genkey: bin/baitkey.o bin/nonce.o bin/sk.o base32.c chacha.o blake2b-ref.o genkey.o randombytes.o tweetnacl.o
	$(CC) -o $@ $^ $(LDFLAGS)

validkey: bin/baitkey.o bin/nonce.o bin/sk.o bin/pk.o bin/random.o base32.c chacha.o blake2b-ref.o randombytes.o tweetnacl.o validkey.o
	$(CC) -o $@ $^ $(LDFLAGS)

bin/baitkey.c: bin/baitkey.pem
	bin2c -o $@ -n baitkey -d bin/baitkey.h $^

bin/nonce.c: bin/nonce.der
	bin2c -o $@ -n nonce_der -d bin/nonce.h $^

bin/pk.c: bin/pk.bin
	bin2c -o $@ -n pk -d bin/pk.h $^

bin/random.c: bin/random.bin
	bin2c -o $@ -n trash -d bin/random.h $^

bin/sk.c: bin/sk.bin
	bin2c -o $@ -n sk -d bin/sk.h $^

bin.h: bin/baitkey.c bin/nonce.c bin/pk.c

genkey.o: bin.h bin/sk.h base32.h chacha.h blake2.h randombytes.h tweetnacl.h

tweetnacl.o: tweetnacl.h

validkey.o: bin.h bin/sk.h base32.h chacha.h blake2.h tweetnacl.h

clean:
	rm -f *.o bin/*.o bin/*.c bin/*.h genkey validkey

strip: 
	strip -s validkey

