#include "hpdf_conf.h"
#include "hpdf_consts.h"
#include "hpdf_error.h"
#include "hpdf_encrypt.h"
#include "hpdf_crypto.h"
#include "hpdf_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#endif

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/syscall.h>
#endif

#include "bearssl_hash.h"
#include "bearssl_block.h"

HPDF_STATUS
HPDF_Crypto_RandomBytes  (HPDF_BYTE  *buf,
                          HPDF_UINT   len)
{
    HPDF_UINT offset = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf (buf, len);
    return HPDF_OK;
#else
    while (offset < len) {
        ssize_t rlen = -1;

#if defined(SYS_getrandom)
        rlen = syscall (SYS_getrandom, buf + offset,
                (size_t)(len - offset), 0);
#endif
        if (rlen > 0) {
            offset += (HPDF_UINT)rlen;
            continue;
        }

        if (rlen < 0 && errno == EINTR)
            continue;
        break;
    }

    if (offset < len) {
        int fd = open ("/dev/urandom", O_RDONLY);
        if (fd < 0)
            return HPDF_UNSUPPORTED_FUNC;

        while (offset < len) {
            ssize_t rlen = read (fd, buf + offset, (size_t)(len - offset));
            if (rlen > 0) {
                offset += (HPDF_UINT)rlen;
                continue;
            }
            if (rlen < 0 && errno == EINTR)
                continue;
            close (fd);
            return HPDF_UNSUPPORTED_FUNC;
        }

        close (fd);
    }

    return HPDF_OK;
#endif
}


HPDF_STATUS
HPDF_Crypto_SHA2  (HPDF_UINT         bits,
                   const HPDF_BYTE  *buf,
                   HPDF_UINT         len,
                   HPDF_BYTE        *digest,
                   HPDF_UINT        *digest_len)
{
    switch (bits) {
    case 256: {
        br_sha256_context ctx;

        br_sha256_init (&ctx);
        br_sha256_update (&ctx, buf, len);
        br_sha256_out (&ctx, digest);
        *digest_len = br_sha256_SIZE;
        return HPDF_OK;
    }
    case 384: {
        br_sha384_context ctx;

        br_sha384_init (&ctx);
        br_sha384_update (&ctx, buf, len);
        br_sha384_out (&ctx, digest);
        *digest_len = br_sha384_SIZE;
        return HPDF_OK;
    }
    case 512: {
        br_sha512_context ctx;

        br_sha512_init (&ctx);
        br_sha512_update (&ctx, buf, len);
        br_sha512_out (&ctx, digest);
        *digest_len = br_sha512_SIZE;
        return HPDF_OK;
    }
    default:
        return HPDF_UNSUPPORTED_FUNC;
    }
}


HPDF_STATUS
HPDF_Crypto_AESCBC_Encrypt  (const HPDF_BYTE  *key,
                             HPDF_UINT         key_len,
                             const HPDF_BYTE  *iv,
                             HPDF_BOOL         use_padding,
                             const HPDF_BYTE  *src,
                             HPDF_UINT         len,
                             HPDF_BYTE        *dst,
                             HPDF_UINT        *dst_len)
{
    HPDF_UINT out_len = len;
    HPDF_BYTE iv_copy[HPDF_AES_BLOCK_SIZE];
    br_aes_small_cbcenc_keys ctx;

    if (use_padding) {
        HPDF_BYTE pad_len = (HPDF_BYTE)(HPDF_AES_BLOCK_SIZE -
                (len % HPDF_AES_BLOCK_SIZE));

        if (pad_len == 0)
            pad_len = HPDF_AES_BLOCK_SIZE;

        out_len += pad_len;
        HPDF_MemCpy (dst, src, len);
        HPDF_MemSet (dst + len, pad_len, pad_len);
    } else {
        if ((len % HPDF_AES_BLOCK_SIZE) != 0)
            return HPDF_INVALID_PARAMETER;
        if (len > 0)
            HPDF_MemCpy (dst, src, len);
    }

    HPDF_MemCpy (iv_copy, iv, sizeof(iv_copy));
    br_aes_small_cbcenc_init (&ctx, key, key_len);
    br_aes_small_cbcenc_run (&ctx, iv_copy, dst, out_len);

    *dst_len = out_len;
    return HPDF_OK;
}


HPDF_STATUS
HPDF_Crypto_AESCBC_EncryptBlocks  (const HPDF_BYTE  *key,
                                   HPDF_UINT         key_len,
                                   HPDF_BYTE        *iv,
                                   const HPDF_BYTE  *src,
                                   HPDF_UINT         len,
                                   HPDF_BYTE        *dst)
{
    br_aes_small_cbcenc_keys ctx;

    if ((len % HPDF_AES_BLOCK_SIZE) != 0)
        return HPDF_INVALID_PARAMETER;

    if (len == 0)
        return HPDF_OK;

    HPDF_MemCpy (dst, src, len);
    br_aes_small_cbcenc_init (&ctx, key, key_len);
    br_aes_small_cbcenc_run (&ctx, iv, dst, len);

    return HPDF_OK;
}
