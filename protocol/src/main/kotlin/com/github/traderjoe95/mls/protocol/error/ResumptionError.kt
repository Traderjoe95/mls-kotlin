package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

sealed interface ReInitError

sealed interface BranchError {
  data class BlankLeavesIncluded(val blank: List<LeafIndex>) : BranchError
}

sealed interface ResumptionError : ReInitError, BranchError

sealed interface ReInitJoinError : WelcomeJoinError {
  data class UnexpectedEpoch(val actual: ULong, val expected: ULong) : ReInitJoinError

  data class GroupIdMismatch(val newGroup: GroupId, val reInitProposal: GroupId) : ReInitJoinError

  data class ExtensionsMismatch(val newGroup: GroupContextExtensions, val reInitProposal: GroupContextExtensions) :
    ReInitJoinError

  data object MembersMissing : ReInitJoinError
}

sealed interface BranchJoinError : WelcomeJoinError

sealed interface ResumptionJoinError : ReInitJoinError, BranchJoinError {
  data class ProtocolVersionMismatch(val newGroup: ProtocolVersion, val required: ProtocolVersion) : ResumptionJoinError

  data class CipherSuiteMismatch(val newGroup: CipherSuite, val required: CipherSuite) : ResumptionJoinError

  data object NewMembersAdded : ResumptionJoinError
}
