package com.github.traderjoe95.mls.protocol.error

sealed interface CreateAddError : NewMemberAddProposalError

sealed interface CreateRemoveError {
  data class MemberIndexOutOfBounds(val memberIdx: UInt, val memberCount: UInt) : CreateRemoveError
}

sealed interface CreateUpdateError {
  data object AlreadyUpdatedThisEpoch : CreateUpdateError
}

sealed interface CreatePreSharedKeyError

sealed interface CreateGroupContextExtensionsError

sealed interface CreateReInitError : ReInitError
