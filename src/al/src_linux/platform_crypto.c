/*
 *  Broadband Forum BUS (Broadband User Services) Work Area
 *
 *  Copyright (c) 2017, Broadband Forum
 *  Copyright (c) 2017, MaxLinear, Inc. and its affiliates
 *
 *  Redistribution and use in source and binary forms, with or
 *  without modification, are permitted provided that the following
 *  conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 *  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  The above license is used as a license under copyright only.
 *  Please reference the Forum IPR Policy for patent licensing terms
 *  <https://www.broadband-forum.org/ipr-policy>.
 *
 *  Any moral rights which are necessary to exercise under the above
 *  license grant are also deemed granted under this license.
 */

#include "platform.h"

#include "openssl/dh.h"   // Diffie Hellman stuff
#include "openssl/bn.h"   // "Big numbers" stuff
#include "openssl/evp.h"  // SHA digest and AES stuff
#include "openssl/hmac.h" // HMAC stuff

#include "platform_crypto.h"

////////////////////////////////////////////////////////////////////////////////
// Private data and functions
////////////////////////////////////////////////////////////////////////////////

// Diffie Hellman group "1536-bit MODP" parameters as specified in RFC3523
// "section 2"
//
static unsigned char dh1536_p[]={
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
        0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
        0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
        0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
        0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
        0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
        0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
        0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
        0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
        0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
        0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
        0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
        0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
        0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
        0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
        0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    };
static unsigned char dh1536_g[]={ 0x02 };


////////////////////////////////////////////////////////////////////////////////
// Platform API: Interface related functions to be used by platform-independent
// files (functions declarations are  found in "../interfaces/platform.h)
////////////////////////////////////////////////////////////////////////////////

INT8U PLATFORM_GET_RANDOM_BYTES(INT8U *p, INT16U len)
{
    FILE   *fd;
    INT32U  rc;

    fd = fopen("/dev/urandom", "rb");

    if (NULL == fd)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("[PLATFORM] Cannot open /dev/urandom\n");
        return 0;
    }

    rc = fread(p, 1, len, fd);

    fclose(fd);

    if (len != rc)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("[PLATFORM] Could not obtain enough random bytes\n");
        return 0;
    }
    else
    {
        return 1;
    }
}

INT8U PLATFORM_GENERATE_DH_KEY_PAIR(INT8U **priv, INT16U *priv_len, INT8U **pub, INT16U *pub_len)
{
    DH *dh;

    if (
         NULL == priv     ||
         NULL == priv_len ||
         NULL == pub      ||
         NULL == pub_len
       )
    {
        return 0;
    }

    if (NULL == (dh = DH_new()))
    {
        return 0;
    }

    // Convert binary to BIGNUM format
    //
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (NULL == (dh->p = BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL)))
    {
        DH_free(dh);
        return 0;
    }
    if (NULL == (dh->g = BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL)))
    {
        DH_free(dh);
        return 0;
    }
#else
    if (!DH_set0_pqg(dh,BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL),NULL,BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL)))
    {
        DH_free(dh);
        return 0;
    }
#endif
    // Obtain key pair
    //
    if (0 == DH_generate_key(dh))
    {
        DH_free(dh);
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    *priv_len = BN_num_bytes(dh->priv_key);
#else
    *priv_len = BN_num_bytes(DH_get0_priv_key(dh));
#endif
    *priv     = (INT8U *)malloc(*priv_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_bn2bin(dh->priv_key, *priv);
#else
    BN_bn2bin(DH_get0_priv_key(dh), *priv);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    *pub_len = BN_num_bytes(dh->pub_key);
#else
    *pub_len = BN_num_bytes(DH_get0_pub_key(dh));
#endif
    *pub     = (INT8U *)malloc(*pub_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_bn2bin(dh->pub_key, *pub);
#else
    BN_bn2bin(DH_get0_pub_key(dh), *pub);
#endif

    DH_free(dh);
      // NOTE: This internally frees "dh->p" and "dh->q", thus no need for us
      // to do anything else.

    return 1;
}

INT8U PLATFORM_COMPUTE_DH_SHARED_SECRET(INT8U **shared_secret, INT16U *shared_secret_len, INT8U *remote_pub, INT16U remote_pub_len, INT8U *local_priv, INT8U local_priv_len)
{
    BIGNUM *pub_key;

    size_t rlen;
    int    keylen;

    DH *dh;

    if (
         NULL == shared_secret     ||
         NULL == shared_secret_len ||
         NULL == remote_pub        ||
         NULL == local_priv
       )
    {
        return 0;
    }

    if (NULL == (dh = DH_new()))
    {
        return 0;
    }

    // Convert binary to BIGNUM format
    //
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (NULL == (dh->p = BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL)))
    {
        DH_free(dh);
        return 0;
    }
    if (NULL == (dh->g = BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL)))
    {
        DH_free(dh);
        return 0;
    }
#else
    if (!DH_set0_pqg(dh,BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL),NULL,BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL)))
    {
        DH_free(dh);
        return 0;
    }
#endif
    if (NULL == (pub_key = BN_bin2bn(remote_pub, remote_pub_len, NULL)))
    {
        DH_free(dh);
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (NULL == (dh->priv_key = BN_bin2bn(local_priv, local_priv_len, NULL)))
    {
        BN_clear_free(pub_key);
        DH_free(dh);
        return 0;
    }
#else
    if(!DH_set0_key(dh,NULL,BN_bin2bn(local_priv, local_priv_len, NULL)))
    {
        BN_clear_free(pub_key);
        DH_free(dh);
        return 0;
    }
#endif

    // Allocate output buffer
    //
    rlen            = DH_size(dh);
    *shared_secret  = (INT8U*)malloc(rlen);

    // Compute the shared secret and save it in the output buffer
    //
    keylen = DH_compute_key(*shared_secret, pub_key, dh);
    if (keylen < 0)
    {
        *shared_secret_len = 0;
        free(*shared_secret);
        *shared_secret = NULL;
        BN_clear_free(pub_key);
        DH_free(dh);

        return 0;
    }
    else
    {
        *shared_secret_len = (INT16U)keylen;
    }

    BN_clear_free(pub_key);
    DH_free(dh);

    return 1;
}


INT8U PLATFORM_SHA256(INT8U num_elem, INT8U **addr, INT32U *len, INT8U *digest)
{
    INT8U res;
    unsigned int  mac_len;
    EVP_MD_CTX   *ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return 0;
    }
#else
    EVP_MD_CTX  ctx_aux;
    ctx = &ctx_aux;

    EVP_MD_CTX_init(ctx);
#endif

    res = 1;

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    {
        res = 0;
    }

    if (1 == res)
    {
        size_t i;

        for (i = 0; i < num_elem; i++)
        {
            if (!EVP_DigestUpdate(ctx, addr[i], len[i]))
            {
                res = 0;
                break;
            }
        }
    }

    if (1 == res)
    {
        if (!EVP_DigestFinal(ctx, digest, &mac_len))
        {
            res = 0;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(ctx);
#endif

    return res;
}


INT8U PLATFORM_HMAC_SHA256(INT8U *key, INT32U keylen, INT8U num_elem, INT8U **addr, INT32U *len, INT8U *hmac)
{
    HMAC_CTX *ctx;
    size_t    i;

    unsigned int mdlen = 32;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = HMAC_CTX_new();
    if (!ctx)
    {
        return 0;
    }
#else
    HMAC_CTX  ctx_aux;
    ctx = &ctx_aux;

    HMAC_CTX_init(ctx);
#endif

    HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);

    for (i = 0; i < num_elem; i++)
    {
        HMAC_Update(ctx, addr[i], len[i]);
    }

    HMAC_Final(ctx, hmac, &mdlen);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return 1;
}

INT8U PLATFORM_AES_ENCRYPT(INT8U *key, INT8U *iv, INT8U *data, INT32U data_len)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx;
#else
    EVP_CIPHER_CTX *ctx;
#endif

    int clen, len;
    INT8U buf[AES_BLOCK_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
#else
    ctx=EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
#endif
    {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
#else
    EVP_CIPHER_CTX_set_padding(ctx, 0);
#endif

    clen = data_len;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_EncryptUpdate(&ctx, data, &clen, data, data_len) != 1 || clen != (int) data_len)
#else
    if (EVP_EncryptUpdate(ctx, data, &clen, data, data_len) != 1 || clen != (int) data_len)
#endif
    {
        return 0;
    }

    len = sizeof(buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_EncryptFinal_ex(&ctx, buf, &len) != 1 || len != 0)
#else
    if (EVP_EncryptFinal_ex(ctx, buf, &len) != 1 || len != 0)
#endif
    {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(&ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}

INT8U PLATFORM_AES_DECRYPT(INT8U *key, INT8U *iv, INT8U *data, INT32U data_len)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx;
#else
    EVP_CIPHER_CTX *ctx;
#endif

    int plen, len;
    INT8U buf[AES_BLOCK_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
#else
    ctx=EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
#endif
    {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
#else
    EVP_CIPHER_CTX_set_padding(ctx, 0);
#endif

    plen = data_len;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_DecryptUpdate(&ctx, data, &plen, data, data_len) != 1 || plen != (int) data_len)
#else
    if (EVP_DecryptUpdate(ctx, data, &plen, data, data_len) != 1 || plen != (int) data_len)
#endif
    {
        return 0;
    }

    len = sizeof(buf);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (EVP_DecryptFinal_ex(&ctx, buf, &len) != 1 || len != 0)
#else
    if (EVP_DecryptFinal_ex(ctx, buf, &len) != 1 || len != 0)
#endif
    {
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(&ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}
