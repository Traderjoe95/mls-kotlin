package com.github.traderjoe95.mls.protocol.psk

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface PskLookup {
  context(ApplicationCtx<Identity>, Raise<PskError>)
  suspend fun <Identity : Any> getPreSharedKey(id: PreSharedKeyId): Secret
}
