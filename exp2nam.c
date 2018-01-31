/**
 * Copyright 2018 Jon DeVree
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static BIO *err;

static EC_KEY *load_key(const char *infile)
{
    BIO *in;
    EC_KEY *key;
    int rc;

    in = BIO_new(BIO_s_file());
    if (in == NULL)
    {
        ERR_print_errors(err);
        return NULL;
    }

    if (infile == NULL)
    {
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    }
    else
    {
        if (BIO_read_filename(in, infile) <= 0)
        {
            ERR_print_errors(err);
            BIO_free(in);
            return NULL;
        }
    }

    key = PEM_read_bio_ECPrivateKey(in, NULL, NULL, NULL);
    if (key == NULL)
    {
        BIO_reset(in);
        key = d2i_ECPrivateKey_bio(in, NULL);
        if (key == NULL)
        {
            ERR_print_errors(err);
            EC_KEY_free(key);
            BIO_free(in);
            return NULL;
        }
    }

    rc = EC_KEY_check_key(key);
    if (rc != 1)
    {
        ERR_print_errors(err);
        EC_KEY_free(key);
        BIO_free(in);
        return NULL;
    }

    BIO_free(in);
    return key;
}

static const EC_GROUP *load_group(const EC_KEY *key)
{
    const EC_GROUP *group;
    int flag;
    int nid;
    int rc;

    group = EC_KEY_get0_group(key);
    if (group == NULL)
    {
        ERR_print_errors(err);
        return NULL;
    }

    nid = EC_GROUP_get_curve_name(group);
    if (nid != NID_undef)
    {
        BIO_printf(err, "key already uses named curve\n");
        return NULL;
    }
    flag = EC_GROUP_get_asn1_flag(group);
    if ((flag & OPENSSL_EC_NAMED_CURVE) == OPENSSL_EC_NAMED_CURVE)
    {
        BIO_printf(err, "key already uses named curve\n");
        return NULL;
    }

    rc = EC_GROUP_check(group, NULL);
    if (rc != 1)
    {
        ERR_print_errors(err);
        return NULL;
    }

    return group;
}

/**
 * XXX here be dragons
 *
 * Set the group to explicit encoding, dump it, and then restore it.
 * This black magic forces the group methods to the generic ones so that
 * EC_GROUP_cmp() will actually work correctly
 */
static EC_GROUP *convert_group(const EC_GROUP *group)
{
    EC_GROUP *tgroup;
    unsigned char *der = NULL;
    unsigned char *oder = NULL;
    int len;
    int flag;

    tgroup = EC_GROUP_dup(group);
    if (tgroup == NULL)
    {
        ERR_print_errors(err);
        return NULL;
    }

    flag = EC_GROUP_get_asn1_flag(tgroup);
    EC_GROUP_set_asn1_flag(tgroup, flag & ~OPENSSL_EC_NAMED_CURVE);

    len = i2d_ECPKParameters(tgroup, &der);
    if (len < 0)
    {
        ERR_print_errors(err);
        EC_GROUP_free(tgroup);
        return NULL;
    }

    EC_GROUP_free(tgroup);

    /* d2i_ECPKParameters() tampers with its input parameter */
    oder = der;
    tgroup = d2i_ECPKParameters(NULL, (const unsigned char **)&der, len);
    if (tgroup == NULL)
    {
        ERR_print_errors(err);
        OPENSSL_free(oder);
        return NULL;
    }

    OPENSSL_free(oder);
    return tgroup;
}

/* this iterates over all known curves and sees if any match the private key */
static int match_group(const EC_GROUP *group)
{
    EC_GROUP *tgroup;
    EC_GROUP *ngroup;
    EC_builtin_curve *curves;
    const char *asn1;
    const char *nist;
    size_t len;
    size_t i;
    int nid;
    int rc;

    len = EC_get_builtin_curves(NULL, 0);
    if (len < 1)
    {
        ERR_print_errors(err);
        return NID_undef;
    }

    curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * len);
    if (curves == NULL)
    {
        ERR_print_errors(err);
        return NID_undef;
    }

    rc = EC_get_builtin_curves(curves, len);
    if (rc != len)
    {
        ERR_print_errors(err);
        OPENSSL_free(curves);
        return NID_undef;
    }

    for (i = 0; i < len; i++)
    {
        nid = curves[i].nid;

        tgroup = EC_GROUP_new_by_curve_name(nid);
        if (tgroup == NULL)
        {
            ERR_print_errors(err);
            OPENSSL_free(curves);
            return NID_undef;
        }

        ngroup = convert_group(tgroup);
        if (ngroup == NULL)
        {
            ERR_print_errors(err);
            EC_GROUP_free(tgroup);
            OPENSSL_free(curves);
            return NID_undef;
        }
        EC_GROUP_free(tgroup);

        rc = EC_GROUP_cmp(group, ngroup, NULL);
        if (rc == -1)
        {
            ERR_print_errors(err);
            EC_GROUP_free(ngroup);
            OPENSSL_free(curves);
            return NID_undef;
        }
        else if (rc == 0)
        {
            EC_GROUP_free(ngroup);
            break;
        }
        EC_GROUP_free(ngroup);
    }

    OPENSSL_free(curves);

    if (i == len)
    {
        BIO_printf(err, "couldn't identify named curve that matches key\n");
        return NID_undef;
    }

    asn1 = OBJ_nid2sn(nid);
    if (asn1 != NULL)
    {
        BIO_printf(err, "ASN1 OID: %s\n", asn1);
    }
    nist = EC_curve_nid2nist(nid);
    if (nist != NULL)
    {
        BIO_printf(err, "NIST CURVE: %s\n", nist);
    }

    return nid;
}

static int set_group_name(EC_KEY *key, const EC_GROUP *group, int nid)
{
    EC_GROUP *ngroup;
    int flag;
    int rc;

    ngroup = EC_GROUP_dup(group);
    if (ngroup == NULL)
    {
        ERR_print_errors(err);
        return 0;
    }

    EC_GROUP_set_curve_name(ngroup, nid);

    flag = EC_GROUP_get_asn1_flag(ngroup);
    EC_GROUP_set_asn1_flag(ngroup, flag | OPENSSL_EC_NAMED_CURVE);

    rc = EC_GROUP_check(ngroup, NULL);
    if (rc != 1)
    {
        ERR_print_errors(err);
        EC_GROUP_free(ngroup);
        return 0;
    }

    rc = EC_KEY_set_group(key, ngroup);
    if (rc != 1)
    {
        ERR_print_errors(err);
        EC_GROUP_free(ngroup);
        return 0;
    }
    EC_GROUP_free(ngroup);

    rc = EC_KEY_check_key(key);
    if (rc != 1)
    {
        ERR_print_errors(err);
        return 0;
    }

    return 1;
}

static int print_key(EC_KEY *key)
{
    BIO *out = NULL;

    out = BIO_new(BIO_s_file());
    if (out == NULL)
    {
        ERR_print_errors(err);
        return 0;
    }

    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    PEM_write_bio_ECPrivateKey(out, key, NULL, NULL, 0, NULL, NULL);

    BIO_free(out);
    return 1;
}

int main(int argc, char **argv)
{
    EC_KEY *key;
    const EC_GROUP *group = NULL;
    char *infile = NULL;
    int rc;
    int nid;

    if (argc == 2)
    {
        infile = argv[1];
    }
    else if (argc != 1)
    {
        fprintf(stderr, "Usage: %s [ec private key]\n", argv[0]);
        exit(1);
    }

    err = BIO_new(BIO_s_file());
    if (err == NULL)
    {
        exit(1);
    }
    BIO_set_fp(err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    key = load_key(infile);
    if (key == NULL)
    {
        BIO_free(err);
        EVP_cleanup();
        ERR_free_strings();
        exit(1);
    }

    group = load_group(key);
    if (group == NULL)
    {
        EC_KEY_free(key);
        BIO_free(err);
        EVP_cleanup();
        ERR_free_strings();
        exit(1);
    }

    nid = match_group(group);
    if (nid == NID_undef)
    {
        EC_KEY_free(key);
        BIO_free(err);
        EVP_cleanup();
        ERR_free_strings();
        exit(1);
    }

    rc = set_group_name(key, group, nid);
    if (rc != 1)
    {
        EC_KEY_free(key);
        BIO_free(err);
        EVP_cleanup();
        ERR_free_strings();
        exit(1);
    }

    rc = print_key(key);
    if (rc != 1)
    {
        EC_KEY_free(key);
        BIO_free(err);
        EVP_cleanup();
        ERR_free_strings();
        exit(1);
    }

    EC_KEY_free(key);
    BIO_free(err);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
