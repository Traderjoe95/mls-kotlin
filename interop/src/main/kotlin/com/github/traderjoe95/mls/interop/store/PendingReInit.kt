package com.github.traderjoe95.mls.interop.store

import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MessageOptions

data class PendingReInit(
  val id: Int,
  val oldGroup: GroupState.Suspended,
  val keyPackage: KeyPackage.Private,
  val handshakeOptions: MessageOptions,
)
