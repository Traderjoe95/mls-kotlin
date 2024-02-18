package com.github.traderjoe95.mls.playground

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

object Config {
  val protocolVersion = ProtocolVersion.MLS_1_0
  val cipherSuite = CipherSuite.X448_CHACHA20_SHA512_ED448
  val cipherSuite2 = CipherSuite.P521_AES256_SHA512_P521
}
