package com.github.traderjoe95.mls.interop.store

import com.github.traderjoe95.mls.interop.HoldsExternalPsks
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.message.MessageOptions
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.util.hex

data class StoredState(
  val id: Int,
  val groupState: GroupState,
  val handshakeOptions: MessageOptions,
  val externalPsks: MutableMap<String, Secret> = mutableMapOf(),
  var pendingCommit: Pair<ByteArray, Int>? = null,
) : HoldsExternalPsks {
  override fun addExternalPsk(
    id: ByteArray,
    psk: Secret,
  ) {
    externalPsks[id.hex] = psk
  }

  override fun getExternalPask(id: ByteArray): Secret? = externalPsks[id.hex]
}
