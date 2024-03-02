package com.github.traderjoe95.mls.protocol.psk

import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface ExternalPskHolder<T : ExternalPskHolder<T>> : PskLookup {
  fun registerExternalPsk(
    pskId: ByteArray,
    psk: Secret,
  ): T

  fun deleteExternalPsk(pskId: ByteArray): T

  fun clearExternalPsks(): T
}
