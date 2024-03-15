package com.github.traderjoe95.mls.interop

import arrow.core.Either
import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface HoldsExternalPsks : PskLookup {
  fun addExternalPsk(
    id: ByteArray,
    psk: Secret,
  )

  fun getExternalPask(id: ByteArray): Secret?

  override suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret> =
    either {
      when (id) {
        is ExternalPskId -> getExternalPask(id.pskId) ?: raise(PskError.PskNotFound(id))
        else -> raise(PskError.PskNotFound(id))
      }
    }
}
