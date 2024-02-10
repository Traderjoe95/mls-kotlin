package com.github.traderjoe95.mls.protocol.crypto.impl

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.hpke.HPKE

internal enum class HashFunction(
  val hashLen: UShort,
  val hkdfId: Short,
) {
  SHA256(32U, HPKE.kdf_HKDF_SHA256),
  SHA384(48U, HPKE.kdf_HKDF_SHA384),
  SHA512(64U, HPKE.kdf_HKDF_SHA512),
  ;

  fun createDigest(): Digest =
    when (this) {
      SHA256 -> SHA256Digest()
      SHA384 -> SHA384Digest()
      SHA512 -> SHA512Digest()
    }
}
