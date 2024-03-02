package com.github.traderjoe95.mls.protocol.psk

import arrow.core.Either
import arrow.core.left
import arrow.core.raise.either
import arrow.core.recover
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface PskLookup {
  suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret>

  companion object {
    suspend fun resolvePsks(
      lookup: PskLookup,
      psks: List<PreSharedKeyId>,
    ): Either<PskError, List<ResolvedPsk>> =
      either {
        psks.map { ResolvedPsk(it, lookup.getPreSharedKey(it).bind()) }
      }

    @JvmStatic
    val EMPTY: PskLookup =
      object : PskLookup {
        override suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret> = PskError.PskNotFound(id).left()
      }

    @JvmStatic
    infix fun PskLookup.delegatingTo(fallback: PskLookup?): PskLookup =
      if (fallback == null) {
        this
      } else {
        object : PskLookup {
          override suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret> =
            this@delegatingTo.getPreSharedKey(id)
              .recover { err ->
                when (err) {
                  is PskError.PskNotFound -> fallback.getPreSharedKey(id).bind()
                  else -> raise(err)
                }
              }
        }
      }
  }
}
