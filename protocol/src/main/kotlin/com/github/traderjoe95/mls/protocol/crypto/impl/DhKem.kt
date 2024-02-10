package com.github.traderjoe95.mls.protocol.crypto.impl

import org.bouncycastle.crypto.hpke.HPKE

internal enum class DhKem(val id: Short, val hash: HashFunction) {
  P256_SHA256(HPKE.kem_P256_SHA256, HashFunction.SHA256),
  P384_SHA384(HPKE.kem_P384_SHA348, HashFunction.SHA384),
  P521_SHA512(HPKE.kem_P521_SHA512, HashFunction.SHA512),
  X25519_SHA256(HPKE.kem_X25519_SHA256, HashFunction.SHA256),
  X448_SHA512(HPKE.kem_X448_SHA512, HashFunction.SHA512),
}
