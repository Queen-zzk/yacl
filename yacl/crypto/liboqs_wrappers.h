#include <string>

#include "oqs/oqs.h"

namespace yacl::crypto {

enum class KyberVariant { kyber512, kyber768, kyber1024 };

std::string ToName(KyberVariant variant) {
  switch (variant) {
    case KyberVariant::kyber512:
      return "kyber512";
    case KyberVariant::kyber768:
      return "kyber768";
    case KyberVariant::kyber1024:
      return "kyber1024";
    default:
      return "Unknown";
  }
}

std::string ToSecurityString(KyberVariant variant) {
  switch (variant) {
    case KyberVariant::kyber512:
      return "1";
    case KyberVariant::kyber768:
      return "3";
    case KyberVariant::kyber1024:
      return "5";
    default:
      return "Unknown";
  }
}

}  // namespace yacl::crypto