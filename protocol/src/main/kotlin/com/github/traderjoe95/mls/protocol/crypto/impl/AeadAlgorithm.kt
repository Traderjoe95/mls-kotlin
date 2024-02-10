package com.github.traderjoe95.mls.protocol.crypto.impl

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.modes.AEADCipher
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.modes.ChaCha20Poly1305 as ChaCha20Poly1305Engine

internal enum class AeadAlgorithm(
  val id: Short,
  val keyLen: UShort,
  val nonceLen: UShort,
) {
  AesGcm128(HPKE.aead_AES_GCM128, 16U, 12U),
  AesGcm256(HPKE.aead_AES_GCM256, 32U, 12U),
  ChaCha20Poly1305(HPKE.aead_CHACHA20_POLY1305, 32U, 12U),
  ;

  fun createCipher(): AEADCipher =
    when (this) {
      AesGcm128, AesGcm256 -> GCMBlockCipher.newInstance(AESEngine.newInstance())
      ChaCha20Poly1305 -> ChaCha20Poly1305Engine()
    }
}
