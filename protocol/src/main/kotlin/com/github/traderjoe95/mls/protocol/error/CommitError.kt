package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode

sealed interface SenderCommitError : ResumptionError

sealed interface RecipientCommitError : ProcessMessageError

sealed interface CommitError : SenderCommitError, RecipientCommitError {
  data object CachedUpdateMissing : CommitError

  data class CachedUpdateDoesNotMatch(val cachedLeafNode: LeafNode<*>, val proposalLeafNode: LeafNode<*>) : CommitError
}

data object RemovedFromGroup : RecipientCommitError

sealed interface InvalidCommit : CommitError {
  data class BadCommitSender(val senderType: SenderType) : InvalidCommit

  data class UnknownProposal(val groupId: GroupId, val epoch: ULong, val ref: Proposal.Ref) : InvalidCommit

  data object UpdateByCommitter : InvalidCommit

  data object CommitterRemoved : InvalidCommit

  data class AmbiguousUpdateOrRemove(val leafIndex: LeafIndex) : InvalidCommit

  data class AlreadyMember(val keyPackage: KeyPackage, val existingLeafIdx: LeafIndex) : InvalidCommit

  data class DoublePsk(val preSharedKeyId: PreSharedKeyId) : InvalidCommit

  data object AmbiguousGroupCtxExtensions : InvalidCommit

  data object ReInitMustBeSingle : InvalidCommit

  data object ExternalInitFromMember : InvalidCommit

  data object MissingUpdatePath : InvalidCommit

  data object MissingExternalInit : InvalidCommit

  data object NoProposalRefAllowed : InvalidCommit

  data object DoubleExternalInit : InvalidCommit

  data object DoubleRemove : InvalidCommit

  data class InvalidExternalProposal(val type: ProposalType) : InvalidCommit
}
