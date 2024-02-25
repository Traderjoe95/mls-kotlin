package com.github.traderjoe95.mls.demo

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

object Config {
  val protocolVersion = ProtocolVersion.MLS_1_0

  val cipherSuite = CipherSuite.X448_CHACHA20_SHA512_ED448
  val reInitCipherSuite = CipherSuite.P384_AES256_SHA512_P384
}
