package com.github.traderjoe95.mls.protocol.crypto.impl

import com.github.traderjoe95.mls.protocol.crypto.Auth
import com.github.traderjoe95.mls.protocol.crypto.Encrypt
import com.github.traderjoe95.mls.protocol.crypto.Gen
import com.github.traderjoe95.mls.protocol.crypto.Hash
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.Kdf
import com.github.traderjoe95.mls.protocol.crypto.Kem
import com.github.traderjoe95.mls.protocol.crypto.Sign
import java.security.SecureRandom

internal class CipherSuiteImpl private constructor(
  sign: SignProvider,
  hpke: Hpke,
  hash: HashProvider,
  hkdf: Hkdf,
) : ICipherSuite,
  Sign by sign,
  Encrypt by hpke,
  Hash by hash,
  Auth by hkdf,
  Kdf by hkdf,
  Kem by hpke,
  Gen by hpke {
  companion object {
    internal fun using(
      dhKem: DhKem,
      aead: AeadAlgorithm,
    ): CipherSuiteImpl {
      val rand = SecureRandom()

      return CipherSuiteImpl(
        SignProvider(dhKem, rand),
        Hpke(dhKem, aead, rand),
        HashProvider(dhKem.hash),
        Hkdf(dhKem.hash),
      )
    }
  }
}
