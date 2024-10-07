#pragma once

#include <memory>
#include <utility>
#include <vector>

#include "yacl/crypto/key_utils.h"
#include "yacl/crypto/pke/asymmetric_crypto.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("kyber512_enc", SecParam::C::k128, SecParam::S::INF);
YACL_MODULE_DECLARE("kyber768_enc", SecParam::C::k192, SecParam::S::INF);
YACL_MODULE_DECLARE("kyber1024_enc", SecParam::C::k256, SecParam::S::INF);

namespace yacl::crypto {

class KyberEncryptor : public AsymmetricEncryptor {
 public:
  explicit KyberEncryptor(openssl::UniquePkey&& pk,
                          AsymCryptoSchema schema = AsymCryptoSchema::KYBER512)
      : pk_(std::move(pk)), schema_(schema) {}
  explicit KyberEncryptor(ByteContainerView pk_buf,
                          AsymCryptoSchema schema = AsymCryptoSchema::KYBER512)
      : pk_(LoadKeyFromBuf(pk_buf)), schema_(schema) {}

  AsymCryptoSchema GetSchema() const override { return schema_; }
  std::vector<uint8_t> Encrypt(ByteContainerView plaintext);

 private:
  const openssl::UniquePkey pk_;
  const AsymCryptoSchema schema_;
};

class KyberDecryptor : public AsymmetricDecryptor {
 public:
  explicit KyberDecryptor(openssl::UniquePkey&& sk,
                          AsymCryptoSchema schema = AsymCryptoSchema::KYBER512)
      : sk_(std::move(sk)), schema_(schema) {}
  explicit KyberDecryptor(ByteContainerView sk_buf,
                          AsymCryptoSchema schema = AsymCryptoSchema::KYBER512)
      : sk_(LoadKeyFromBuf(sk_buf)), schema_(schema) {}

  AsymCryptoSchema GetSchema() const override { return schema_; }
  std::vector<uint8_t> Decrypt(ByteContainerView ciphertext);

 private:
  const openssl::UniquePkey sk_;
  const AsymCryptoSchema schema_;
};

}  // namespace yacl::crypto