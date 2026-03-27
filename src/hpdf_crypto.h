#ifndef HPDF_CRYPTO_H
#define HPDF_CRYPTO_H

#include "hpdf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

HPDF_STATUS
HPDF_Crypto_RandomBytes  (HPDF_BYTE  *buf,
                          HPDF_UINT   len);

HPDF_STATUS
HPDF_Crypto_SHA2  (HPDF_UINT         bits,
                   const HPDF_BYTE  *buf,
                   HPDF_UINT         len,
                   HPDF_BYTE        *digest,
                   HPDF_UINT        *digest_len);

HPDF_STATUS
HPDF_Crypto_AESCBC_Encrypt  (const HPDF_BYTE  *key,
                             HPDF_UINT         key_len,
                             const HPDF_BYTE  *iv,
                             HPDF_BOOL         use_padding,
                             const HPDF_BYTE  *src,
                             HPDF_UINT         len,
                             HPDF_BYTE        *dst,
                             HPDF_UINT        *dst_len);

#ifdef __cplusplus
}
#endif

#endif
