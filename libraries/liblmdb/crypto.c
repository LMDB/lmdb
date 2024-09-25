/* crypto.c - LMDB encryption helper module */
/*
 * Copyright 2020-2021 Howard Chu, Symas Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the Symas
 * Dual-Use License.
 *
 * A copy of this license is available in the file LICENSE in the
 * source distribution.
 */
#include <string.h>

#include <openssl/engine.h>

#include "lmdb.h"

MDB_crypto_hooks MDB_crypto;

static EVP_CIPHER *cipher;

static int mcf_str2key(const char *passwd, MDB_val *key)
{
	unsigned int size;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, "Just a Constant", sizeof("Just a Constant"));
	EVP_DigestUpdate(mdctx, passwd, strlen(passwd));
	EVP_DigestFinal_ex(mdctx, key->mv_data, &size);
	EVP_MD_CTX_free(mdctx);
	return 0;
}

/* cheats - internal OpenSSL 1.1 structures
 * These are copied from the OpenSSL source code.
 *
 * We use these to allow stack allocation of these structures
 * and to prevent OpenSSL from malloc'ing and free'ing them,
 * which would be too slow.
 */
typedef struct my_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
#if OPENSSL_VERSION_NUMBER >= 0x30006000
    int iv_len;                 /* IV length */
#endif
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    /*
     * Opaque ctx returned from a providers cipher algorithm implementation
     * OSSL_FUNC_cipher_newctx()
     */
    void *algctx;
    EVP_CIPHER *fetched_cipher;
#endif
} MY_CIPHER_CTX;

typedef struct evp_cipher_head {
	int nid;
	int block_size;
	int key_len;
	int iv_len;
	unsigned long flags;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
	int origin;
#endif
	int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int enc);
} evp_cipher_head;

#define	CHACHA_KEY_SIZE	32
#define CHACHA_CTR_SIZE	16
#define CHACHA_BLK_SIZE	64
#define POLY1305_BLOCK_SIZE	16

typedef struct {
    union {
        double align;   /* this ensures even sizeof(EVP_CHACHA_KEY)%8==0 */
        unsigned int d[CHACHA_KEY_SIZE / 4];
    } key;
    unsigned int  counter[CHACHA_CTR_SIZE / 4];
    unsigned char buf[CHACHA_BLK_SIZE];
    unsigned int  partial_len;
} MY_CHACHA_KEY;

typedef struct {
    MY_CHACHA_KEY key;
    unsigned int nonce[12/4];
    unsigned char tag[POLY1305_BLOCK_SIZE];
    unsigned char tls_aad[POLY1305_BLOCK_SIZE];
    struct { uint64_t aad, text; } len;
    int aad, mac_inited, tag_len, nonce_len;
    size_t tls_payload_length;
} MY_CHACHA_AEAD_CTX;

typedef struct {
	double opaque[24];
	unsigned int nonce[4];
	unsigned char data[POLY1305_BLOCK_SIZE];
	size_t num;
	struct {
		void (*foo1)();
		void (*foo2)();
	} func;
} my_poly1305_ctx;

typedef struct my_cipherdata {
	MY_CHACHA_AEAD_CTX aead_ctx;
	my_poly1305_ctx poly_ctx;
} my_cipherdata;

static int mcf_encfunc(const MDB_val *src, MDB_val *dst, const MDB_val *key, int encdec)
{
	unsigned char iv[12];
	int ivl, outl, rc;
	mdb_size_t *ptr;
	MY_CIPHER_CTX myctx = {0};
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)&myctx;
	my_cipherdata cactx = {0};
	evp_cipher_head *eh = (evp_cipher_head *)cipher;

	ptr = key[1].mv_data;
	ivl = ptr[0] & 0xffffffff;
	memcpy(iv, &ivl, 4);
	memcpy(iv+4, ptr+1, sizeof(mdb_size_t));
	EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encdec);

	/* we can't set cipher_data before calling CipherInit because
	 * that will just try to free it. So set it now, and then finish
	 * up the other two Init calls that we disabled before.
	 */
	myctx.cipher_data = &cactx;
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, NULL);
	eh->init(ctx, key[0].mv_data, iv, encdec);

	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (!encdec) {
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, key[2].mv_size, key[2].mv_data);
	}
	rc = EVP_CipherUpdate(ctx, dst->mv_data, &outl, src->mv_data, src->mv_size);
	if (rc)
		rc = EVP_CipherFinal_ex(ctx, key[2].mv_data, &outl);
	if (rc && encdec) {
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, key[2].mv_size, key[2].mv_data);
	}
	return rc == 0;
}

static const MDB_crypto_funcs mcf_table = {
	mcf_str2key,
	mcf_encfunc,
	NULL,
	CHACHA_KEY_SIZE,
	POLY1305_BLOCK_SIZE,
	0
};

MDB_crypto_funcs *MDB_crypto()
{
	evp_cipher_head *eh;
	cipher = (EVP_CIPHER *)EVP_chacha20_poly1305();

	/* We must disable the implicit init calls */
	eh = (evp_cipher_head *)cipher;
	eh->flags &= ~(EVP_CIPH_CTRL_INIT|EVP_CIPH_ALWAYS_CALL_INIT);

	return (MDB_crypto_funcs *)&mcf_table;
}
