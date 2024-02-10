package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities

sealed interface WelcomeJoinError {
  data object NoMatchingKeyPackage : WelcomeJoinError

  data class WrongCipherSuite(val expected: CipherSuite, val actual: CipherSuite) : WelcomeJoinError

  data object OwnLeafNotFound : WelcomeJoinError

  data object MultipleResumptionPsks : WelcomeJoinError

  data class WrongResumptionEpoch(val epoch: ULong) : WelcomeJoinError
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
    val capabilities: Capabilities, val unsupported: List<GroupContextExtension<*>>
  ) : ExtensionSupportError
}


