#include <string.h>

#include <openssl/engine.h>

#include "lmdb.h"

MDB_crypto_hooks MDB_crypto;

static EVP_CIPHER *cipher;

static int str2key(const char *passwd, MDB_val *key)
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

static int encfunc(const MDB_val *src, MDB_val *dst, const MDB_val *key, int encdec)
{
	unsigned char iv[12];
	int ivl, outl, rc;
	mdb_size_t *ptr;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	ptr = key[1].mv_data;
	ivl = ptr[0] & 0xffffffff;
	memcpy(iv, &ivl, 4);
	memcpy(iv+4, ptr+1, sizeof(mdb_size_t));
	EVP_CipherInit_ex(ctx, cipher, NULL, key[0].mv_data, iv, encdec);
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
	EVP_CIPHER_CTX_free(ctx);
	return rc == 0;
}

static const MDB_crypto_funcs table = {
	str2key,
	encfunc,
	NULL,
	32,
	16,
	0
};

MDB_crypto_funcs *MDB_crypto()
{
	cipher = (EVP_CIPHER *)EVP_chacha20_poly1305();
	return (MDB_crypto_funcs *)&table;
}
