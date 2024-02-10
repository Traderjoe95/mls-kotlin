package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey

sealed interface SenderTreeUpdateError : SenderCommitError, ExternalJoinError

sealed interface RecipientTreeUpdateError : RecipientCommitError

sealed interface TreeUpdateError : SenderTreeUpdateError, RecipientTreeUpdateError

data class WrongUpdatePathLength(
  val filteredDirectPathLength: UInt,
  val updatePathLength: UInt,
) : RecipientTreeUpdateError

data class WrongParentHash(
  val computed: ByteArray,
  val found: ByteArray,
) : RecipientTreeUpdateError

data class PublicKeyMismatch(
  val derived: HpkePublicKey,
  val found: HpkePublicKey,
) : RecipientTreeUpdateError, JoinError
