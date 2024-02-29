package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface Gen {
  fun generateSecret(len: UShort): Secret

  fun generateNonce(len: UShort): Nonce

  fun generateHpkeKeyPair(): HpkeKeyPair
}
