#include <sys/queue.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/x509.h>

#include "extern.h"

int
socket_blocking(int fd, int verb)
{
	int	 fl;

	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		WARN("fcntl");
	else if (fcntl(fd, F_SETFL, fl & ~O_NONBLOCK) == -1)
		WARN("fcntl");
	else
		return 1;
	return 0;
}

int
socket_nonblocking(int fd, int verb)
{
	int	 fl;

	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		WARN("fcntl");
	else if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1)
		WARN("fcntl");
	else
		return 1;
	return 0;
}

/*
 * Blocking write of a binary buffer.
 * Return zero on failure, non-zero otherwise.
 */
int
simple_write(int fd, const void *res, size_t sz)
{
	ssize_t	 ssz;

	if (sz == 0)
		return 1;
	if ((ssz = write(fd, res, sz)) < 0)
		WARN("write");
	return ssz >= 0;
}

/*
 * Like simple_write() but into a buffer.
 */
void
simple_buffer(char **b, size_t *bsz,
	size_t *bmax, const void *res, size_t sz)
{

	if (*bsz + sz > *bmax) {
		if ((*b = realloc(*b, *bsz + sz)) == NULL)
			err(EXIT_FAILURE, NULL);
		*bmax = *bsz + sz;
	}

	memcpy(*b + *bsz, res, sz);
	*bsz += sz;
}

/*
 * Like buf_write() but into a buffer.
 */
void
buf_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const void *p, size_t sz)
{

	simple_buffer(b, bsz, bmax, &sz, sizeof(size_t));
	if (sz > 0)
		simple_buffer(b, bsz, bmax, p, sz);
}

/*
 * Write a binary buffer of the given size.
 * Return zero on failure, non-zero on success.
 */
int
buf_write(int fd, int verb, const void *p, size_t sz)
{

	if (!simple_write(fd, &sz, sizeof(size_t)))
		WARNX1(verb, "simple_write");
	else if (sz > 0 && !simple_write(fd, p, sz))
		WARNX1(verb, "simple_write");
	else
		return 1;
	return 0;
}

/*
 * Like str_write() but into a buffer.
 */
void
str_buffer(char **b, size_t *bsz, size_t *bmax, int verb, const char *p)
{
	size_t	 sz = (p == NULL) ? 0 : strlen(p);

	buf_buffer(b, bsz, bmax, verb, p, sz);
}

/*
 * Write a NUL-terminated string, which may be zero-length.
 * Return zero on failure, non-zero on success.
 */
int
str_write(int fd, int verb, const char *p)
{
	size_t	 sz = (p == NULL) ? 0 : strlen(p);

	if (!buf_write(fd, verb, p, sz))
		WARNX1(verb, "buf_write");
	else
		return 1;
	return 0;
}

/*
 * Blocking read of a binary buffer w/o end of file.
 * Return zero on failure, non-zero otherwise.
 */
int
simple_read(int fd, int verb, void *res, size_t sz)
{
	ssize_t	 ssz;

	if ((ssz = read(fd, res, sz)) < 0)
		WARN("read");
	else if (ssz == 0)
		WARNX(verb, "unexpected end of file");
	else
		return 1;
	return 0;
}

/*
 * Read a binary buffer, allocating space for it.
 * If the buffer is zero-sized, this won't allocate "res".
 * Return zero on failure, non-zero otherwise.
 * On failure, result pointers are set to NULL/0.
 */
int
buf_read_alloc(int fd, int verb, void **res, size_t *sz)
{

	*res = NULL;
	if (!simple_read(fd, verb, sz, sizeof(size_t)))
		WARNX1(verb, "simple_read");
	else if (*sz > 0 && (*res = malloc(*sz)) == NULL)
		err(EXIT_FAILURE, NULL);
	else if (*sz > 0 && !simple_read(fd, verb, *res, *sz))
		WARNX1(verb, "simple_read");
	else
		return 1;

	free(*res);
	*res = NULL;
	*sz = 0;
	return 0;
}

/*
 * Read a string (which may just be \0), allocating space for it.
 * Return zero on failure, non-zero otherwise.
 * On failure, result is always NULL.
 */
int
str_read(int fd, int verb, char **res)
{
	size_t	 sz;

	if (!simple_read(fd, verb, &sz, sizeof(size_t)))
		WARNX1(verb, "simple_read");
	else if ((*res = calloc(sz + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);
	else if (!simple_read(fd, verb, *res, sz))
		WARNX1(verb, "simple_read");
	else
		return 1;

	free(*res);
	*res = NULL;
	return 0;
}