package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.Either
import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.error.MacError
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface Auth {
  fun mac(
    secret: Secret,
    content: ByteArray,
  ): Mac

  fun verifyMac(
    secret: Secret,
    content: ByteArray,
    mac: Mac,
  ): Either<MacError, Unit> =
    either {
      val equal =
        mac(secret, content).bytes
          .zip(mac.bytes)
          .fold(true) { eq, (l, r) -> eq && l == r }

      if (!equal) raise(MacError.BadMac)
    }
}
