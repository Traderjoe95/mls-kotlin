package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.error.ReconstructHpkePublicKeyError
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface Kem {
  fun deriveKeyPair(secret: Secret): HpkeKeyPair

  fun reconstructPublicKey(privateKey: HpkePrivateKey): Either<ReconstructHpkePublicKeyError, HpkeKeyPair>
}
