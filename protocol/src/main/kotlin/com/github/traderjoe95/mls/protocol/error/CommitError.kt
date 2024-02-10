package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import de.traderjoe.ulid.ULID

sealed interface SenderCommitError : ResumptionError

sealed interface RecipientCommitError

sealed interface CommitError : SenderCommitError, RecipientCommitError

data object RemovedFromGroup : RecipientCommitError

sealed interface InvalidCommit : CommitError {
  data class BadCommitSender(val senderType: SenderType) : InvalidCommit

  data class UnknownProposal(val groupId: ULID, val epoch: ULong, val ref: Proposal.Ref) : InvalidCommit

  data object UpdateByCommitter : InvalidCommit

  data object CommitterRemoved : InvalidCommit

  data class AmbiguousUpdateOrRemove(val leafIndex: UInt) : InvalidCommit

  data class DoubleAdd(val keyPackage: KeyPackage) : InvalidCommit

  data class ReAdd(val keyPackage: KeyPackage) : InvalidCommit

  data class KeyPackageInvalidCipherSuite(val cipherSuite: CipherSuite, val expected: CipherSuite) : InvalidCommit

  data class DoublePsk(val preSharedKeyId: PreSharedKeyId) : InvalidCommit

  data object AmbiguousGroupCtxExtensions : InvalidCommit

  data object ReInitMustBeSingle : InvalidCommit

  data object ExternalInitFromMember : InvalidCommit

  data object MissingUpdatePath : InvalidCommit

  data object MissingExternalInit : InvalidCommit

  data object NoProposalRefAllowed : InvalidCommit

  data object DoubleExternalInit : InvalidCommit

  data object DoubleRemove : InvalidCommit

  data class UnauthorizedExternalRemove(val leafIndex: UInt) : InvalidCommit

  data class InvalidExternalProposal(val type: ProposalType) : InvalidCommit
}
