#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"
#include "openssl/evp.h"
#include "openssl/core_names.h"

#define MAC_KEY_BYTES 32
#define MAC_TAG_BYTES 16

/**
 * uint8_t *key: pointer to the symmetric key. The symmetric key is an array of POLY1305_KEY_BYTES
 */
void mac_poly1305(uint8_t *key,
                  uint8_t *msg,
                  size_t msglen,
                  uint8_t *digest) {
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mac_ctx = NULL;
    size_t _;

    mac = EVP_MAC_fetch(NULL, "Poly1305", NULL);
    mac_ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, MAC_KEY_BYTES);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC_CTX_set_params(mac_ctx, params);
    EVP_MAC_init(mac_ctx, key, MAC_KEY_BYTES, params);
    EVP_MAC_update(mac_ctx, msg, msglen);
    EVP_MAC_final(mac_ctx, digest, &_, MAC_TAG_BYTES);

    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);
}


/*************************************************
* Name:        crypto_kem_keypair_derand
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*              - uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_derand(uint8_t *pk,
                              uint8_t *sk,
                              const uint8_t *coins)
{
  indcpa_keypair_derand(pk, sk, coins);
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  uint8_t coins[2*KYBER_SYMBYTES];
  randombytes(coins, 2*KYBER_SYMBYTES);
  crypto_kem_keypair_derand(pk, sk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
int crypto_kem_enc_derand(uint8_t *ct,
                          uint8_t *ss,
                          const uint8_t *pk,
                          const uint8_t *coins)
{
  // coins correspond to an IND-CPA plaintext
  // buf is plaintext || SHA3-256(pk)
  uint8_t buf[2*KYBER_SYMBYTES];
  // kr will be filled with shared secrets || IND-CPA coin
  uint8_t kr[2*KYBER_SYMBYTES];

  memcpy(buf, coins, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  // because Kyber round 4 uses the rigid transformation with implicit rejection, hashing the
  // plaintext alone is sufficient for deriving the shared secret, though the design also added in
  // the hash of the public key for preventing multitarget attacks
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  memcpy(ss,kr,KYBER_SYMBYTES);
  return 0;
}

/**
 * For implementing the KEM using "encrypt-then-MAC":
 * Param: uint8_t *ct is still a pointer to a bytes array, but the length of the bytes array will be
 *        KYBER_CIPHERTEXTBYTES + AUTHENTICATOR_BYTES
 * Param: uint8_t *ss remains the same
 * Param: const uint8_t *pk remains the same
 * Param: const uint8_t *indcpa_pt will be a randomly selected IND-CPA plaintext, which corresponds
 *        to the argument "coins" in crypto_kem_enc_derand(ct, ss, pk, coins)
 * Param: const uint8_t *indcpa_coin will be a randomly selected coin that will feed into the
 *        function call for indcpa_enc(ct, buf, pk, coin);
 *
 * We will use SHA3-512 to hash (m || h) into (preKey || macKey), after encrypting m into ct, we
 * need to sign the ciphertext, but then the shared secret is a hash of (preKey || tag) where the
 * tag is a hash of the ciphertext.
 * so we need three buffers:
 * uint8_t mh[2 * kyber_symbytes];   // will hold m and h, where h is hash of public key
 * uint8_t kk[kyber_symbytes + authenticator_key_bytes];  // will hold preKey and mac key
 * uint8_t kt[kyber_symbytes + authenticator_tag_bytes];  // will hold preKey and tag
 *
 * finally a hash of kt will produce the shared secret
 */
int crypt_kem_etm_encap_derand(uint8_t *ct,
                               uint8_t *ss,
                               const uint8_t *pk,
                               const uint8_t *indcpa_pt,
                               const uint8_t *indcpa_coin) {
  // TODO: implement this method and write a test about it
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
  crypto_kem_enc_derand(ct, ss, pk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* Compute rejection key */
  rkprf(ss,sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,ct);

  /* Copy true key to return buffer if fail is false */
  cmov(ss,kr,KYBER_SYMBYTES,!fail);

  return 0;
}
