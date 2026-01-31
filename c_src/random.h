#ifndef SECP256K1_NIF_RANDOM_H
#define SECP256K1_NIF_RANDOM_H

#if defined(_WIN32)
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/random.h>
#include <stdio.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#else
#error "Couldn't identify the OS"
#endif

#endif /* SECP256K1_NIF_RANDOM_H */

/* Returns 1 on success, and 0 on failure. */
static int fill_random(unsigned char *data, size_t size)
{
#if defined(_WIN32)
    NTSTATUS res = BCryptGenRandom(NULL, data, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (res != STATUS_SUCCESS || size > ULONG_MAX)
    {
        return 0;
    }
    else
    {
        return 1;
    }
#elif defined(__linux__) || defined(__FreeBSD__)
    /* If `getrandom(2)` is not available you should fallback to /dev/urandom */
    ssize_t res = getrandom(data, size, 0);
    if (res < 0 || (size_t)res != size)
    {
        FILE *fp = fopen("/dev/urandom", "rb");
        if (!fp)
        {
            return 0;
        }
        size_t read_bytes = fread(data, 1, size, fp);
        fclose(fp);
        if (read_bytes != size)
        {
            return 0;
        }
        return 1;
    }
    else
    {
        return 1;
    }
#elif defined(__APPLE__) || defined(__OpenBSD__)
    /* If `getentropy(2)` is not available you should fallback to either
     * `SecRandomCopyBytes` or /dev/urandom */
    int res = getentropy(data, size);
    if (res == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
#endif
    return 0;
}
