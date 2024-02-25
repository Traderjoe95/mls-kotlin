package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities

sealed interface WelcomeJoinError {
  data object WelcomeNotForYou : WelcomeJoinError

  data object OwnLeafNotFound : WelcomeJoinError

  data object MultipleResumptionPsks : WelcomeJoinError

  data class WrongResumptionEpoch(val epoch: ULong) : WelcomeJoinError

  data class MissingResumptionGroup(val pskId: ResumptionPskId) : WelcomeJoinError
}

sealed interface ExternalJoinError {
  data object MissingExternalPub : ExternalJoinError
}

sealed interface JoinError : WelcomeJoinError, ExternalJoinError {
  data object MissingRatchetTree : JoinError

  data object AlreadyMember : JoinError
}

sealed interface ExtensionSupportError : JoinError, GroupCreationError {
  data class UnsupportedGroupContextExtensions(
    val capabilities: Capabilities,
    val unsupported: List<GroupContextExtension<*>>,
  ) : ExtensionSupportError
}
