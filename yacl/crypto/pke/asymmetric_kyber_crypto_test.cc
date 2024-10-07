#include "yacl/crypto/pke/asymmetric_kyber_crypto.h"

#include <string>

#include "gtest/gtest.h"

namespace yacl::crypto {

TEST(AsymmetricKyber, EncryptDecrypt_shouldOk) {
  // GIVEN
  auto [pk, sk] = GenKyberKeyPairToPemBuf();
  std::string m = "I am a plaintext.";

  // WHEN
  auto enc_ctx = KyberEncryptor(pk);
  auto dec_ctx = KyberDecryptor(sk);

  auto c = enc_ctx.Encrypt(m);
  auto m_check = dec_ctx.Decrypt(c);

  // THEN
  EXPECT_EQ(std::memcmp(m.data(), m_check.data(), m.size()), 0);
}

}  // namespace yacl::crypto