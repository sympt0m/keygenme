/*
 * randombytes.c: generate cryptographically secure random bytes.
 * Probably requires more side-channel attack safety.
 *
 * Inspired by
 * https://insanecoding.blogspot.com/2014/05/a-good-idea-with-bad-usage-devurandom.html
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "randombytes.h"

#define FUCK(x) do { panic("%s:%u: %s", __func__, __LINE__, (x)); } while (0)

static _Noreturn void
panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

static int
superread(int fd, void *buf, size_t len)
{
	size_t total = 0;
	ssize_t nr;

	while (total < len)
	{
		nr = read(fd, (unsigned char *)buf + total, len - total);
		if (nr > 0)
			total += (size_t)nr;
		else if (nr == 0)
			break;
		else if (errno != EINTR)
			return -1;
	}

	return 0;
}

void
randombytes(void *buf, size_t len)
{
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		FUCK("fd");

	if (superread(fd, buf, len) != 0)
		FUCK("superread");

	close(fd);
}

