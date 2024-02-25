package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.error.MacError
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface Auth {
  fun mac(
    secret: Secret,
    content: ByteArray,
  ): Mac

  context(Raise<MacError>)
  fun verifyMac(
    secret: Secret,
    content: ByteArray,
    mac: Mac,
  ) {
    if (mac(secret, content).bytes.contentEquals(mac.bytes).not()) raise(MacError.BadMac)
  }
}
