/* osurandom engine
 *
 * Windows         CryptGenRandom()
 * macOS >= 10.12  getentropy()
 * OpenBSD 5.6+    getentropy()
 * other BSD       getentropy() if SYS_getentropy is defined
 * Linux 3.17+     getrandom() with fallback to /dev/urandom
 * other           /dev/urandom with cached fd
 *
 * The /dev/urandom, getrandom and getentropy code is derived from Python's
 * Python/random.c, written by Antoine Pitrou and Victor Stinner.
 *
 * Copyright 2001-2016 Python Software Foundation; All Rights Reserved.
 */

#ifdef __linux__
#include <poll.h>
#endif

#if CRYPTOGRAPHY_NEEDS_OSRANDOM_ENGINE
/* OpenSSL has ENGINE support and is older than 1.1.1d (the first version that
 * properly implements fork safety in its RNG) so build the engine. */
static const char *Cryptography_osrandom_engine_id = "osrandom";

/****************************************************************************
 * Windows
 */
#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_CRYPTGENRANDOM
static const char *Cryptography_osrandom_engine_name = "osrandom_engine CryptGenRandom()";
static HCRYPTPROV hCryptProv = 0;

static int osrandom_init(ENGINE *e) {
    if (hCryptProv != 0) {
        return 1;
    }
    if (CryptAcquireContext(&hCryptProv, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return 1;
    } else {
        ERR_Cryptography_OSRandom_error(
            CRYPTOGRAPHY_OSRANDOM_F_INIT,
            CRYPTOGRAPHY_OSRANDOM_R_CRYPTACQUIRECONTEXT,
            __FILE__, __LINE__
        );
        return 0;
    }
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    if (hCryptProv == 0) {
        return 0;
    }

    if (!CryptGenRandom(hCryptProv, (DWORD)size, buffer)) {
        ERR_Cryptography_OSRandom_error(
            CRYPTOGRAPHY_OSRANDOM_F_RAND_BYTES,
            CRYPTOGRAPHY_OSRANDOM_R_CRYPTGENRANDOM,
            __FILE__, __LINE__
        );
        return 0;
    }
    return 1;
}

static int osrandom_finish(ENGINE *e) {
    if (CryptReleaseContext(hCryptProv, 0)) {
        hCryptProv = 0;
        return 1;
    } else {
        ERR_Cryptography_OSRandom_error(
            CRYPTOGRAPHY_OSRANDOM_F_FINISH,
            CRYPTOGRAPHY_OSRANDOM_R_CRYPTRELEASECONTEXT,
            __FILE__, __LINE__
        );
        return 0;
    }
}

static int osrandom_rand_status(void) {
    return hCryptProv != 0;
}

static const char *osurandom_get_implementation(void) {
    return "CryptGenRandom";
}

#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_CRYPTGENRANDOM */

/****************************************************************************
 * /dev/urandom helpers for all non-BSD Unix platforms
 */
#ifdef CRYPTOGRAPHY_OSRANDOM_NEEDS_DEV_URANDOM

static struct {
    int fd;
    dev_t st_dev;
    ino_t st_ino;
} urandom_cache = { -1 };

static int open_cloexec(const char *path) {
    int open_flags = O_RDONLY;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif

    int fd = open(path, open_flags);
    if (fd == -1) {
        return -1;
    }

#ifndef O_CLOEXEC
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        return -1;
    }
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
        return -1;
    }
#endif
    return fd;
}

#ifdef __linux__
/* On Linux, we open("/dev/random") and use poll() to wait until it's readable
 * before we read from /dev/urandom, this ensures that we don't read from
 * /dev/urandom before the kernel CSPRNG is initialized. This isn't necessary on
 * other platforms because they don't have the same _bug_ as Linux does with
 * /dev/urandom and early boot. */
static int wait_on_devrandom(void) {
    struct pollfd pfd = {};
    int ret = 0;
    int random_fd = open_cloexec("/dev/random");
    if (random_fd < 0) {
        return -1;
    }
    pfd.fd = random_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    do {
        ret = poll(&pfd, 1, -1);
    } while (ret < 0 && (errno == EINTR || errno == EAGAIN));
    close(random_fd);
    return ret;
}
#endif

/* return -1 on error */
static int dev_urandom_fd(void) {
    int fd = -1;
    struct stat st;

    /* Check that fd still points to the correct device */
    if (urandom_cache.fd >= 0) {
        if (fstat(urandom_cache.fd, &st)
                || st.st_dev != urandom_cache.st_dev
                || st.st_ino != urandom_cache.st_ino) {
            /* Somebody replaced our FD. Invalidate our cache but don't
             * close the fd. */
            urandom_cache.fd = -1;
        }
    }
    if (urandom_cache.fd < 0) {
#ifdef __linux__
        if (wait_on_devrandom() < 0) {
            goto error;
        }
#endif

        fd = open_cloexec("/dev/urandom");
        if (fd < 0) {
            goto error;
        }
        if (fstat(fd, &st)) {
            goto error;
        }
        /* Another thread initialized the fd */
        if (urandom_cache.fd >= 0) {
            close(fd);
            return urandom_cache.fd;
        }
        urandom_cache.st_dev = st.st_dev;
        urandom_cache.st_ino = st.st_ino;
        urandom_cache.fd = fd;
    }
    return urandom_cache.fd;

  error:
    if (fd != -1) {
        close(fd);
    }
    ERR_Cryptography_OSRandom_error(
        CRYPTOGRAPHY_OSRANDOM_F_DEV_URANDOM_FD,
        CRYPTOGRAPHY_OSRANDOM_R_DEV_URANDOM_OPEN_FAILED,
        __FILE__, __LINE__
    );
    return -1;
}

static int dev_urandom_read(unsigned char *buffer, int size) {
    int fd;
    int n;

    fd = dev_urandom_fd();
    if (fd < 0) {
        return 0;
    }

    while (size > 0) {
        do {
            n = (int)read(fd, buffer, (size_t)size);
        } while (n < 0 && errno == EINTR);

        if (n <= 0) {
            ERR_Cryptography_OSRandom_error(
                CRYPTOGRAPHY_OSRANDOM_F_DEV_URANDOM_READ,
                CRYPTOGRAPHY_OSRANDOM_R_DEV_URANDOM_READ_FAILED,
                __FILE__, __LINE__
            );
            return 0;
        }
        buffer += n;
        size -= n;
    }
    return 1;
}

static void dev_urandom_close(void) {
    if (urandom_cache.fd >= 0) {
        int fd;
        struct stat st;

        if (fstat(urandom_cache.fd, &st)
                && st.st_dev == urandom_cache.st_dev
                && st.st_ino == urandom_cache.st_ino) {
            fd = urandom_cache.fd;
            urandom_cache.fd = -1;
            close(fd);
        }
    }
}
#endif /* CRYPTOGRAPHY_OSRANDOM_NEEDS_DEV_URANDOM */

/****************************************************************************
 * BSD getentropy
 */
#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_GETENTROPY
static const char *Cryptography_osrandom_engine_name = "osrandom_engine getentropy()";

static int getentropy_works = CRYPTOGRAPHY_OSRANDOM_GETENTROPY_NOT_INIT;

static int osrandom_init(ENGINE *e) {
#if !defined(__APPLE__)
    getentropy_works = CRYPTOGRAPHY_OSRANDOM_GETENTROPY_WORKS;
#else
    if (__builtin_available(macOS 10.12, *)) {
        getentropy_works = CRYPTOGRAPHY_OSRANDOM_GETENTROPY_WORKS;
    } else {
        getentropy_works = CRYPTOGRAPHY_OSRANDOM_GETENTROPY_FALLBACK;
        int fd = dev_urandom_fd();
        if (fd < 0) {
            return 0;
        }
    }
#endif
    return 1;
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    int len;
    int res;

    switch(getentropy_works) {
#if defined(__APPLE__)
    case CRYPTOGRAPHY_OSRANDOM_GETENTROPY_FALLBACK:
        return dev_urandom_read(buffer, size);
#endif
    case CRYPTOGRAPHY_OSRANDOM_GETENTROPY_WORKS:
        while (size > 0) {
            /* OpenBSD and macOS restrict maximum buffer size to 256. */
            len = size > 256 ? 256 : size;
/* on mac, availability is already checked using `__builtin_available` above */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability"
            res = getentropy(buffer, (size_t)len);
#pragma clang diagnostic pop
            if (res < 0) {
                ERR_Cryptography_OSRandom_error(
                    CRYPTOGRAPHY_OSRANDOM_F_RAND_BYTES,
                    CRYPTOGRAPHY_OSRANDOM_R_GETENTROPY_FAILED,
                    __FILE__, __LINE__
                );
                return 0;
            }
            buffer += len;
            size -= len;
        }
        return 1;
    }
    __builtin_unreachable();
}

static int osrandom_finish(ENGINE *e) {
    return 1;
}

static int osrandom_rand_status(void) {
    return 1;
}

static const char *osurandom_get_implementation(void) {
    switch(getentropy_works) {
    case CRYPTOGRAPHY_OSRANDOM_GETENTROPY_FALLBACK:
        return "/dev/urandom";
    case CRYPTOGRAPHY_OSRANDOM_GETENTROPY_WORKS:
        return "getentropy";
    }
    __builtin_unreachable();
}
#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_GETENTROPY */

/****************************************************************************
 * Linux getrandom engine with fallback to dev_urandom
 */

#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_GETRANDOM
static const char *Cryptography_osrandom_engine_name = "osrandom_engine getrandom()";

static int getrandom_works = CRYPTOGRAPHY_OSRANDOM_GETRANDOM_NOT_INIT;

static int osrandom_init(ENGINE *e) {
    /* We try to detect working getrandom until we succeed. */
    if (getrandom_works != CRYPTOGRAPHY_OSRANDOM_GETRANDOM_WORKS) {
        long n;
        char dest[1];
        /* if the kernel CSPRNG is not initialized this will block */
        n = syscall(SYS_getrandom, dest, sizeof(dest), 0);
        if (n == sizeof(dest)) {
            getrandom_works = CRYPTOGRAPHY_OSRANDOM_GETRANDOM_WORKS;
        } else {
            int e = errno;
            switch(e) {
            case ENOSYS:
                /* Fallback: Kernel does not support the syscall. */
                getrandom_works = CRYPTOGRAPHY_OSRANDOM_GETRANDOM_FALLBACK;
                break;
            case EPERM:
                /* Fallback: seccomp prevents syscall */
                getrandom_works = CRYPTOGRAPHY_OSRANDOM_GETRANDOM_FALLBACK;
                break;
            default:
                /* EINTR cannot occur for buflen < 256. */
                ERR_Cryptography_OSRandom_error(
                    CRYPTOGRAPHY_OSRANDOM_F_INIT,
                    CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_INIT_FAILED_UNEXPECTED,
                    "errno", e
                );
                getrandom_works = CRYPTOGRAPHY_OSRANDOM_GETRANDOM_INIT_FAILED;
                break;
            }
        }
    }

    /* fallback to dev urandom */
    if (getrandom_works == CRYPTOGRAPHY_OSRANDOM_GETRANDOM_FALLBACK) {
        int fd = dev_urandom_fd();
        if (fd < 0) {
            return 0;
        }
    }
    return 1;
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    long n;

    switch(getrandom_works) {
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_INIT_FAILED:
        ERR_Cryptography_OSRandom_error(
            CRYPTOGRAPHY_OSRANDOM_F_RAND_BYTES,
            CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_INIT_FAILED,
            __FILE__, __LINE__
        );
        return 0;
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_NOT_INIT:
        ERR_Cryptography_OSRandom_error(
            CRYPTOGRAPHY_OSRANDOM_F_RAND_BYTES,
            CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_NOT_INIT,
            __FILE__, __LINE__
        );
        return 0;
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_FALLBACK:
        return dev_urandom_read(buffer, size);
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_WORKS:
        while (size > 0) {
            do {
                n = syscall(SYS_getrandom, buffer, size, 0);
            } while (n < 0 && errno == EINTR);

            if (n <= 0) {
                ERR_Cryptography_OSRandom_error(
                    CRYPTOGRAPHY_OSRANDOM_F_RAND_BYTES,
                    CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_FAILED,
                    __FILE__, __LINE__
                );
                return 0;
            }
            buffer += n;
            size -= (int)n;
        }
        return 1;
    }
    __builtin_unreachable();
}

static int osrandom_finish(ENGINE *e) {
    dev_urandom_close();
    return 1;
}

static int osrandom_rand_status(void) {
    switch(getrandom_works) {
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_INIT_FAILED:
        return 0;
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_NOT_INIT:
        return 0;
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_FALLBACK:
        return urandom_cache.fd >= 0;
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_WORKS:
        return 1;
    }
    __builtin_unreachable();
}

static const char *osurandom_get_implementation(void) {
    switch(getrandom_works) {
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_INIT_FAILED:
        return "<failed>";
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_NOT_INIT:
        return "<not initialized>";
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_FALLBACK:
        return "/dev/urandom";
    case CRYPTOGRAPHY_OSRANDOM_GETRANDOM_WORKS:
        return "getrandom";
    }
    __builtin_unreachable();
}
#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_GETRANDOM */

/****************************************************************************
 * dev_urandom engine for all remaining platforms
 */

#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_DEV_URANDOM
static const char *Cryptography_osrandom_engine_name = "osrandom_engine /dev/urandom";

static int osrandom_init(ENGINE *e) {
    int fd = dev_urandom_fd();
    if (fd < 0) {
        return 0;
    }
    return 1;
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    return dev_urandom_read(buffer, size);
}

static int osrandom_finish(ENGINE *e) {
    dev_urandom_close();
    return 1;
}

static int osrandom_rand_status(void) {
    return urandom_cache.fd >= 0;
}

static const char *osurandom_get_implementation(void) {
    return "/dev/urandom";
}
#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_DEV_URANDOM */

/****************************************************************************
 * ENGINE boiler plate
 */

/* This replicates the behavior of the OpenSSL FIPS RNG, which returns a
   -1 in the event that there is an error when calling RAND_pseudo_bytes. */
static int osrandom_pseudo_rand_bytes(unsigned char *buffer, int size) {
    int res = osrandom_rand_bytes(buffer, size);
    if (res == 0) {
        return -1;
    } else {
        return res;
    }
}

static RAND_METHOD osrandom_rand = {
    NULL,
    osrandom_rand_bytes,
    NULL,
    NULL,
    osrandom_pseudo_rand_bytes,
    osrandom_rand_status,
};

static const ENGINE_CMD_DEFN osrandom_cmd_defns[] = {
    {CRYPTOGRAPHY_OSRANDOM_GET_IMPLEMENTATION,
     "get_implementation",
     "Get CPRNG implementation.",
     ENGINE_CMD_FLAG_NO_INPUT},
     {0, NULL, NULL, 0}
};

static int osrandom_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void)) {
    const char *name;
    size_t len;

    switch (cmd) {
    case CRYPTOGRAPHY_OSRANDOM_GET_IMPLEMENTATION:
        /* i: buffer size, p: char* buffer */
        name = osurandom_get_implementation();
        len = strlen(name);
        if ((p == NULL) && (i == 0)) {
            /* return required buffer len */
            return (int)len;
        }
        if ((p == NULL) || i < 0 || ((size_t)i <= len)) {
            /* no buffer or buffer too small */
            ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_INVALID_ARGUMENT);
            return 0;
        }
        strcpy((char *)p, name);
        return (int)len;
    default:
        ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED);
        return 0;
    }
}

/* error reporting */
#define ERR_FUNC(func) ERR_PACK(0, func, 0)
#define ERR_REASON(reason) ERR_PACK(0, 0, reason)

static ERR_STRING_DATA CRYPTOGRAPHY_OSRANDOM_lib_name[] = {
    {0, "osrandom_engine"},
    {0, NULL}
};

static ERR_STRING_DATA CRYPTOGRAPHY_OSRANDOM_str_funcs[] = {
    {ERR_FUNC(CRYPTOGRAPHY_OSRANDOM_F_INIT),
     "osrandom_init"},
    {ERR_FUNC(CRYPTOGRAPHY_OSRANDOM_F_RAND_BYTES),
     "osrandom_rand_bytes"},
    {ERR_FUNC(CRYPTOGRAPHY_OSRANDOM_F_FINISH),
     "osrandom_finish"},
    {ERR_FUNC(CRYPTOGRAPHY_OSRANDOM_F_DEV_URANDOM_FD),
     "dev_urandom_fd"},
    {ERR_FUNC(CRYPTOGRAPHY_OSRANDOM_F_DEV_URANDOM_READ),
     "dev_urandom_read"},
    {0, NULL}
};

static ERR_STRING_DATA CRYPTOGRAPHY_OSRANDOM_str_reasons[] = {
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_CRYPTACQUIRECONTEXT),
     "CryptAcquireContext() failed."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_CRYPTGENRANDOM),
     "CryptGenRandom() failed."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_CRYPTRELEASECONTEXT),
     "CryptReleaseContext() failed."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_GETENTROPY_FAILED),
     "getentropy() failed"},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_DEV_URANDOM_OPEN_FAILED),
     "open('/dev/urandom') failed."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_DEV_URANDOM_READ_FAILED),
     "Reading from /dev/urandom fd failed."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_INIT_FAILED),
     "getrandom() initialization failed."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_INIT_FAILED_UNEXPECTED),
     "getrandom() initialization failed with unexpected errno."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_FAILED),
     "getrandom() syscall failed."},
    {ERR_REASON(CRYPTOGRAPHY_OSRANDOM_R_GETRANDOM_NOT_INIT),
     "getrandom() engine was not properly initialized."},
    {0, NULL}
};

static int Cryptography_OSRandom_lib_error_code = 0;

static void ERR_load_Cryptography_OSRandom_strings(void)
{
    if (Cryptography_OSRandom_lib_error_code == 0) {
        Cryptography_OSRandom_lib_error_code = ERR_get_next_error_library();
        ERR_load_strings(Cryptography_OSRandom_lib_error_code,
                         CRYPTOGRAPHY_OSRANDOM_lib_name);
        ERR_load_strings(Cryptography_OSRandom_lib_error_code,
                         CRYPTOGRAPHY_OSRANDOM_str_funcs);
        ERR_load_strings(Cryptography_OSRandom_lib_error_code,
                         CRYPTOGRAPHY_OSRANDOM_str_reasons);
    }
}

static void ERR_Cryptography_OSRandom_error(int function, int reason,
                                            char *file, int line)
{
    ERR_PUT_error(Cryptography_OSRandom_lib_error_code, function, reason,
                  file, line);
}

/* Returns 1 if successfully added, 2 if engine has previously been added,
   and 0 for error. */
int Cryptography_add_osrandom_engine(void) {
    ENGINE *e;

    ERR_load_Cryptography_OSRandom_strings();

    e = ENGINE_by_id(Cryptography_osrandom_engine_id);
    if (e != NULL) {
        ENGINE_free(e);
        return 2;
    } else {
        ERR_clear_error();
    }

    e = ENGINE_new();
    if (e == NULL) {
        return 0;
    }
    if (!ENGINE_set_id(e, Cryptography_osrandom_engine_id) ||
            !ENGINE_set_name(e, Cryptography_osrandom_engine_name) ||
            !ENGINE_set_RAND(e, &osrandom_rand) ||
            !ENGINE_set_init_function(e, osrandom_init) ||
            !ENGINE_set_finish_function(e, osrandom_finish) ||
            !ENGINE_set_cmd_defns(e, osrandom_cmd_defns) ||
            !ENGINE_set_ctrl_function(e, osrandom_ctrl)) {
        ENGINE_free(e);
        return 0;
    }
    if (!ENGINE_add(e)) {
        ENGINE_free(e);
        return 0;
    }
    if (!ENGINE_free(e)) {
        return 0;
    }

    return 1;
}

#else
/* If OpenSSL has no ENGINE support then we don't want
 * to compile the osrandom engine, but we do need some
 * placeholders */
static const char *Cryptography_osrandom_engine_id = "no-engine-support";
static const char *Cryptography_osrandom_engine_name = "osrandom_engine disabled";

int Cryptography_add_osrandom_engine(void) {
    return 0;
}

#endif

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*SignFunc)(unsigned char *sig, size_t *sig_len,
                         const unsigned char *tbs, size_t tbs_len);

// template <typename T, typename Ret, Ret (*Deleter)(T *)>
// struct OpenSSLDeleter {
//   void operator()(T *t) const { Deleter(t); }
// };
// struct OpenSSLFreeDeleter {
//   void operator()(unsigned char *buf) const { OPENSSL_free(buf); }
// };
// template <typename T, void (*Deleter)(T *)>
// using OwnedOpenSSLPtr = std::unique_ptr<T, OpenSSLDeleter<T, void, Deleter>>;
// template <typename T, int (*Deleter)(T *)>
// using OwnedOpenSSLPtrIntRet =
//     std::unique_ptr<T, OpenSSLDeleter<T, int, Deleter>>;
// using OwnedBIO = OwnedOpenSSLPtrIntRet<BIO, BIO_free>;
// using OwnedENGINE = OwnedOpenSSLPtrIntRet<ENGINE, ENGINE_free>;
// using OwnedEVP_MD_CTX = OwnedOpenSSLPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
// using OwnedEVP_PKEY = OwnedOpenSSLPtr<EVP_PKEY, EVP_PKEY_free>;
// using OwnedEVP_PKEY_METHOD =
//     OwnedOpenSSLPtr<EVP_PKEY_METHOD, EVP_PKEY_meth_free>;
// using OwnedSSL_CTX = OwnedOpenSSLPtr<SSL_CTX, SSL_CTX_free>;
// using OwnedSSL = OwnedOpenSSLPtr<SSL, SSL_free>;
// using OwnedX509_PUBKEY = OwnedOpenSSLPtr<X509_PUBKEY, X509_PUBKEY_free>;
// using OwnedX509 = OwnedOpenSSLPtr<X509, X509_free>;
// using OwnedOpenSSLBuffer = std::unique_ptr<uint8_t, OpenSSLFreeDeleter>;

// Part 1. First we need a way to attach `CustomKey` to `EVP_PKEY`s that we will
// hand to OpenSSL. OpenSSL does this with "ex data". The following
// `SetCustomKey` and `GetCustomKey` provide the setter and getter methods.

// "ex data" will be allocated once globally by `CreateEngineOnceGlobally`
// method.
int g_rsa_ex_index = -1, g_ec_ex_index = -1;

void FreeExData(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
                void *argp) {
  // CustomKey is created by ConfigureSslContext, so we need to delete the
  // CustomKey stored in ex_data.
  free(ptr);
}

int SetCustomKey(EVP_PKEY *pkey, SignFunc key) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    LogInfo("setting RSA custom key");
    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa && RSA_set_ex_data(rsa, g_rsa_ex_index, key);
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    LogInfo("setting EC custom key");
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    return ec_key && EC_KEY_set_ex_data(ec_key, g_ec_ex_index, key);
  }
  return 0;
}

SignFunc GetCustomKey(EVP_PKEY *pkey) {
  if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    return rsa ? RSA_get_ex_data(rsa, g_rsa_ex_index) : NULL;
  }
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    return ec_key ? EC_KEY_get_ex_data(ec_key, g_ec_ex_index) : NULL;
  }
  return NULL;
}

// Part 2. Next we make an `EVP_PKEY_METHOD` that can call `CustomKey::Sign`.

// As OpenSSL sets up an `EVP_PKEY_CTX`, it will configure it with
// `EVP_PKEY_CTRL_*` calls. This structure collects all the values.
typedef struct {
  const EVP_MD *md;
  int rsa_padding;
  int rsa_pss_salt_len;
  const EVP_MD *rsa_pss_mgf1_md;
} OpenSSLParams;

int CustomInit(EVP_PKEY_CTX *ctx) {
  OpenSSLParams *openssl_params = (OpenSSLParams*) malloc(sizeof(OpenSSLParams));
  openssl_params->md = NULL;
  openssl_params->rsa_padding = RSA_PKCS1_PADDING;
  openssl_params->rsa_pss_salt_len = -2;
  openssl_params->rsa_pss_mgf1_md = NULL;
  EVP_PKEY_CTX_set_data(ctx, openssl_params);
  return 1;
}

void CustomCleanup(EVP_PKEY_CTX *ctx) {
  OpenSSLParams *params = (OpenSSLParams *)EVP_PKEY_CTX_get_data(ctx);
  free(params);
}

int CustomCtrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  OpenSSLParams *params = (OpenSSLParams *)EVP_PKEY_CTX_get_data(ctx);
  // `EVP_PKEY_CTRL_*` values correspond to `EVP_PKEY_CTX` APIs. See
  // https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_get_signature_md.html
  switch (type) {
    case EVP_PKEY_CTRL_MD:  // EVP_PKEY_CTX_set_signature_md
      params->md = (const EVP_MD *)p2;
      return 1;
    case EVP_PKEY_CTRL_GET_MD:  // EVP_PKEY_CTX_get_signature_md
      *((const EVP_MD **)p2) = params->md;
      return 1;
    case EVP_PKEY_CTRL_RSA_PADDING:  // EVP_PKEY_CTX_set_rsa_padding
      params->rsa_padding = p1;
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_PADDING:  // EVP_PKEY_CTX_get_rsa_padding
      *((int *)p2) = params->rsa_padding;
      return 1;
    case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:  // EVP_PKEY_CTX_set_rsa_pss_saltlen
      params->rsa_pss_salt_len = p1;
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:  // EVP_PKEY_CTX_get_rsa_pss_saltlen
      *((int *)p2) = params->rsa_pss_salt_len;
      return 1;
    case EVP_PKEY_CTRL_RSA_MGF1_MD:  // EVP_PKEY_CTX_set_rsa_mgf1_md
      // OpenSSL never actually configures this and relies on the default, but
      // it is, in theory, part of the PSS API.
      params->rsa_pss_mgf1_md = (const EVP_MD *)p2;
      return 1;
    case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:  // EVP_PKEY_CTX_get_rsa_mgf1_md
      // If unspecified, the MGF-1 digest defaults to the signing digest.
      *((const EVP_MD **)p2) =
          params->rsa_pss_mgf1_md ? params->rsa_pss_mgf1_md : params->md;
      return 1;
  }
  return 0;
}

// This function will call CustomKey::Sign to sign the digest of tbs (the bytes
// to be signed) and write back to sig (the signature holder). The supported
// algorithms are:
// (1) ECDSA with SHA256
// (2) RSAPSS with SHA256, MGF-1, salt length = digest length
int CustomDigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *sig_len,
                     const unsigned char *tbs, size_t tbs_len) {
  EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(ctx);

  // Grab the custom key.
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
  if (!pkey) {
    LogInfo("Could not get EVP_PKEY");
    return 0;
  }
  SignFunc key =
      GetCustomKey(EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx)));
  if (!key) {
    LogInfo("Could not get CustomKey from EVP_PKEY");
    return 0;
  }

  // For signature scheme, we only support
  // (1) ECDSA with SHA256
  // (2) RSAPSS with SHA256, MGF-1, salt length = digest length
  if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
    const EVP_MD *md;
    if (EVP_PKEY_CTX_get_signature_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported ECDSA hash");
      return 0;
    }
  } else if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
    const EVP_MD *md;
    if (EVP_PKEY_CTX_get_signature_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported ECDSA hash");
      return 0;
    }
    int val;
    if (EVP_PKEY_CTX_get_rsa_padding(pctx, &val) != 1 ||
        val != RSA_PKCS1_PSS_PADDING) {
      LogInfo("Unsupported RSA padding");
      return 0;
    }
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pctx, &md) != 1 ||
        EVP_MD_nid(md) != NID_sha256) {
      LogInfo("Unsupported RSA-PSS MGF-1 hash");
      return 0;
    }
    // The salt length could either be specified explicitly, or as -1.
    if (EVP_PKEY_CTX_get_rsa_pss_saltlen(pctx, &val) != 1 ||
        (val != EVP_MD_size(md) && val != -1)) {
      LogInfo("Unsupported RSA-PSS salt length");
      return 0;
    }
  } else {
    LogInfo("Unsupported key");
    return 0;
  }

  int res = key(sig, sig_len, tbs, tbs_len);

  return res;
}

// Each `EVP_PKEY_METHOD` is associated with a key type, so we must make a
// separate one for each.
EVP_PKEY_METHOD* MakeCustomMethod(int nid) {
  EVP_PKEY_METHOD* method = EVP_PKEY_meth_new(
      nid, EVP_PKEY_FLAG_SIGCTX_CUSTOM | EVP_PKEY_FLAG_AUTOARGLEN);
  if (!method) {
    return NULL;
  }

  EVP_PKEY_meth_set_init(method, CustomInit);
  EVP_PKEY_meth_set_cleanup(method, CustomCleanup);
  EVP_PKEY_meth_set_ctrl(method, CustomCtrl, NULL);
  EVP_PKEY_meth_set_digestsign(method, CustomDigestSign);
  return method;
}

// Part 3. OpenSSL doesn't pick up our `EVP_PKEY_METHOD` unless it is wrapped in
// an `ENGINE`. We don't `ENGINE_add` this engine, to avoid it accidentally
// overriding normal keys.

// These variables will be created once globally by `CreateEngineOnceGlobally`.
EVP_PKEY_METHOD *g_custom_rsa_pkey_method, *g_custom_ec_pkey_method;

int EngineGetMethods(ENGINE *e, EVP_PKEY_METHOD **out_method,
                     const int **out_nids, int nid) {
  if (!out_method) {
    static const int kNIDs[] = {EVP_PKEY_EC, EVP_PKEY_RSA};
    *out_nids = kNIDs;
    return sizeof(kNIDs) / sizeof(kNIDs[0]);
  }

  switch (nid) {
    case EVP_PKEY_EC:
      *out_method = g_custom_ec_pkey_method;
      return 1;
    case EVP_PKEY_RSA:
      *out_method = g_custom_rsa_pkey_method;
      return 1;
  }
  return 0;
}

// Part 4. Now we can make custom `EVP_PKEY`s that wrap our `CustomKey` objects.
// Note we require the caller provide the public key, here in a certificate.
// This is necessary so OpenSSL knows how much to size its various buffers.

EVP_PKEY* MakeCustomEvpPkey(SignFunc custom_key, X509 *cert,
                                ENGINE *custom_engine) {
  unsigned char *spki = NULL;
  int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spki);
  if (spki_len < 0) {
    return NULL;
  }

  const unsigned char *ptr = spki;
  X509_PUBKEY* pubkey=d2i_X509_PUBKEY(NULL, &ptr, spki_len);
  if (!pubkey) {
    return NULL;
  }

  if (!pubkey || !EVP_PKEY_set1_engine(pubkey, custom_engine) ||
      !SetCustomKey(pubkey, custom_key)) {
    return NULL;
  }
  return pubkey;
}

// Part 5. Now we can attach the CustomKey and cert to SSL context.

int AttachKeyCertToSslContext(SignFunc custom_key, const char *cert,
                               SSL_CTX *ctx, ENGINE *custom_engine) {
  BIO* bio = BIO_new_mem_buf(cert, strlen(cert));
  if (!bio) {
    return 0;
  }
  X509* x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

  EVP_PKEY* wrapped_key =
      MakeCustomEvpPkey(custom_key, x509, custom_engine);
  if (!wrapped_key) {
    return 0;
  }

  static const char *sig_algs_list = "RSA-PSS+SHA256:ECDSA+SHA256";
  if (!SSL_CTX_set1_sigalgs_list(ctx, sig_algs_list)) {
    return 0;
  }
  if (!SSL_CTX_use_PrivateKey(ctx, wrapped_key)) {
    return 0;
  }
  if (!SSL_CTX_use_certificate(ctx, x509)) {
    return 0;
  }
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    return 0;
  }
  return 1;
}

// Part 6. The following functions create a OpenSSL engine, during which all the
// `g_*` global variables such as `g_rsa/ec_ex_index`,
// `g_custom_rsa/ec_pkey_method` etc will be initialized. Note that
// `CreateEngineOnceGlobally` should be used because it creates all these global
// variables and the engine only once, and it is thread safe.

ENGINE *CreateEngineHelper() {
  // Allocate "ex data". We need a way to attach `CustomKey` to `EVP_PKEY`s that
  // we will hand to OpenSSL. OpenSSL does this with "ex data"
  g_rsa_ex_index =
      RSA_get_ex_new_index(0, NULL, NULL, NULL, FreeExData);
  g_ec_ex_index =
      EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, FreeExData);
  if (g_rsa_ex_index < 0 || g_ec_ex_index < 0) {
    // LogInfo("Error allocating ex data");
    return NULL;
  }

  // Create custom method
  g_custom_rsa_pkey_method = MakeCustomMethod(EVP_PKEY_RSA);
  g_custom_ec_pkey_method = MakeCustomMethod(EVP_PKEY_EC);
  if (!g_custom_rsa_pkey_method || !g_custom_ec_pkey_method) {
    // LogInfo("failed to make custom methods");
    return NULL;
  }

  // Ceate a custom engine
  ENGINE* engine = ENGINE_new();
  if (!engine || !ENGINE_set_pkey_meths(engine, EngineGetMethods)) {
    // LogInfo("failed to init engine");
    return NULL;
  }
  return engine;
}

static ENGINE *custom_engine = NULL;
ENGINE *CreateEngineOnceGlobally() {
  if (!custom_engine) {
    custom_engine = CreateEngineHelper();
  }
  return custom_engine;
}

// Part 7. The function below is exported to the compiled shared library
// binary. For all these function, we need to add `extern "C"` to avoid name
// mangling, and `__declspec(dllexport)` for Windows.
// Note that the caller owns the memory for all the pointers passed in as a
// parameter, and caller is responsible for freeing these memories.

// Configure the SSL context to use the provide client side cert and custom key.
#ifdef _WIN32
    __declspec(dllexport)
#endif
        int ConfigureSslContext(SignFunc sign_func, const char *cert,
                                SSL_CTX *ctx) {
  if (!sign_func) {
    return 0;
  }

  if (!cert) {
    return 0;
  }

  if (!ctx) {
    return 0;
  }

  ENGINE *custom_engine = CreateEngineOnceGlobally();
  if (!custom_engine) {
    // LogInfo("failed to create engine");
    return 0;
  }

  // The created custom_key will be deleted by FreeExData.
  if (!AttachKeyCertToSslContext(sign_func, cert, ctx, custom_engine)) {
    return 0;
  }
//   LogInfo("ConfigureSslContext is successful");
  return 1;
}
