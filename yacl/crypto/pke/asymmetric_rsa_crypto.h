// Copyright 2019 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <memory>
#include <utility>
#include <vector>

#include "yacl/crypto/key_utils.h"
#include "yacl/crypto/pke/asymmetric_crypto.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("rsa2048_enc", SecParam::C::k112, SecParam::S::INF);
YACL_MODULE_DECLARE("rsa3072_enc", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

// RSA with OAEP
class RsaEncryptor : public AsymmetricEncryptor {
 public:
  explicit RsaEncryptor(
      openssl::UniquePkey&& pk,
      AsymCryptoSchema schema = AsymCryptoSchema::RSA2048_OAEP)
      : pk_(std::move(pk)), schema_(schema) {}
  explicit RsaEncryptor(
      /* pem key */ ByteContainerView pk_buf,
      AsymCryptoSchema schema = AsymCryptoSchema::RSA2048_OAEP)
      : pk_(LoadKeyFromBuf(pk_buf)), schema_(schema) {}

  AsymCryptoSchema GetSchema() const override { return schema_; }
  std::vector<uint8_t> Encrypt(ByteContainerView plaintext) override;

 private:
  const openssl::UniquePkey pk_;
  const AsymCryptoSchema schema_;
};

class RsaDecryptor : public AsymmetricDecryptor {
 public:
  explicit RsaDecryptor(
      openssl::UniquePkey&& sk,
      AsymCryptoSchema schema = AsymCryptoSchema::RSA2048_OAEP)
      : sk_(std::move(sk)), schema_(schema) {}
  explicit RsaDecryptor(
      /* pem key */ ByteContainerView sk_buf,
      AsymCryptoSchema schema = AsymCryptoSchema::RSA2048_OAEP)
      : sk_(LoadKeyFromBuf(sk_buf)), schema_(schema) {}

  AsymCryptoSchema GetSchema() const override { return schema_; }
  std::vector<uint8_t> Decrypt(ByteContainerView ciphertext) override;

 private:
  const openssl::UniquePkey sk_;
  const AsymCryptoSchema schema_;
};

}  // namespace yacl::crypto
