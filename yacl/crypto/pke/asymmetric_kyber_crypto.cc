#include "yacl/crypto/pke/asymmetric_kyber_crypto.h"

#include <vector>

#include "oqs/kem_kyber.h"

#include "yacl/base/exception.h"

/* oqs/kem_kyber.h defines the following:
#define OQS_KEM_kyber_512_length_public_key 800
#define OQS_KEM_kyber_512_length_secret_key 1632
#define OQS_KEM_kyber_512_length_ciphertext 768
#define OQS_KEM_kyber_512_length_shared_secret 32

#define OQS_KEM_kyber_768_length_public_key 1184
#define OQS_KEM_kyber_768_length_secret_key 2400
#define OQS_KEM_kyber_768_length_ciphertext 1088
#define OQS_KEM_kyber_768_length_shared_secret 32

#define OQS_KEM_kyber_1024_length_public_key 1568
#define OQS_KEM_kyber_1024_length_secret_key 3168
#define OQS_KEM_kyber_1024_length_ciphertext 1568
#define OQS_KEM_kyber_1024_length_shared_secret 32

*/

namespace yacl::crypto {

std::vector<uint8_t> KyberEncryptor::Encrypt(ByteContainerView plaintext) {
  auto ctx = openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(pk_.get(), /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);

  // init context
  OSSL_RET_1(EVP_PKEY_encrypt_init(ctx.get()));

  // kyber's output length is fixed according to the variant
  size_t outlen = 0;
  switch (schema_) {
    case AsymCryptoSchema::KYBER512:
      outlen = OQS_KEM_kyber_512_length_ciphertext;
      break;
    case AsymCryptoSchema::KYBER768:
      outlen = OQS_KEM_kyber_768_length_ciphertext;
      break;
    case AsymCryptoSchema::KYBER1024:
      outlen = OQS_KEM_kyber_1024_length_ciphertext;
    default:
      OSSL_RET_1(EVP_PKEY_encrypt(ctx.get(), /* empty input */ nullptr, &outlen,
                                  plaintext.data(), plaintext.size()));
      break;
  }

  // then encrypt
  std::vector<uint8_t> out(outlen);
  OSSL_RET_1(EVP_PKEY_encrypt(ctx.get(), out.data(), &outlen, plaintext.data(),
                              plaintext.size()));

  out.resize(outlen); /* important */
  return out;
}

std::vector<uint8_t> KyberDecryptor::Decrypt(ByteContainerView ciphertext) {
  auto ctx = openssl::UniquePkeyCtx(
      EVP_PKEY_CTX_new(sk_.get(), /* engine = default */ nullptr));
  YACL_ENFORCE(ctx != nullptr);

  // init context
  OSSL_RET_1(EVP_PKEY_decrypt_init(ctx.get()));

  // first, get output length
  size_t outlen = 0;
  OSSL_RET_1(EVP_PKEY_decrypt(ctx.get(), /* empty input */ nullptr, &outlen,
                              ciphertext.data(), ciphertext.size()));

  // then decrypt
  std::vector<uint8_t> out(outlen);
  OSSL_RET_1(EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, ciphertext.data(),
                              ciphertext.size()));

  out.resize(outlen); /* important */
  return out;
}

}  // namespace yacl::crypto