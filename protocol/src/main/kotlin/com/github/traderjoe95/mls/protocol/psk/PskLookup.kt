package com.github.traderjoe95.mls.protocol.psk

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface PskLookup {
  context(Raise<PskError>)
  suspend fun getPreSharedKey(id: PreSharedKeyId): Secret

  companion object {
    val EMPTY: PskLookup =
      object : PskLookup {
        context(Raise<PskError>)
        override suspend fun getPreSharedKey(id: PreSharedKeyId): Secret = raise(PskError.PskNotFound(id))
      }
  }
}
