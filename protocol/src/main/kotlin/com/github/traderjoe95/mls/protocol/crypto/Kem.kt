package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface Kem {
  fun deriveKeyPair(secret: Secret): HpkeKeyPair

  fun reconstructPublicKey(privateKey: HpkePrivateKey): HpkeKeyPair
}
