package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.error.CommitError
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update

internal typealias ResolvedProposals = MutableMap<ProposalType, List<Pair<Proposal, LeafIndex?>>>

context(Raise<CommitError>)
internal fun ResolvedProposals.validateMember(committerLeafIdx: LeafIndex) {
  val removes = getAll<Remove>(ProposalType.Remove)
  val updates = getAll<Update>(ProposalType.Update)

  if (removes.any { it.first.removed == committerLeafIdx }) {
    raise(InvalidCommit.CommitterRemoved)
  }

  if (updates.any { it.second == committerLeafIdx }) {
    raise(InvalidCommit.UpdateByCommitter)
  }

  val updateAndRemoveCounts =
    sequence {
      yieldAll(removes.map { it.first.removed })
      yieldAll(updates.map { it.second!! })
    }.groupingBy { it }.eachCount().filterValues { it > 1 }

  updateAndRemoveCounts
    .filterValues { it > 1 }
    .firstNotNullOfOrNull { it.key }
    ?.also { raise(InvalidCommit.AmbiguousUpdateOrRemove(it)) }

  getAll<PreSharedKey>(ProposalType.Psk).apply {
    checkDuplicates()
  }

  getAll<GroupContextExtensions>(ProposalType.GroupContextExtensions).apply {
    if (size > 1) raise(InvalidCommit.AmbiguousGroupCtxExtensions)
  }

  getAll<ReInit>(ProposalType.ReInit).apply {
    if (size > 1) {
      raise(InvalidCommit.ReInitMustBeSingle)
    } else if (size == 1 && this@validateMember.size > 1) {
      raise(InvalidCommit.ReInitMustBeSingle)
    }
  }

  getAll<ExternalInit>(ProposalType.ExternalInit).apply {
    if (isNotEmpty()) raise(InvalidCommit.ExternalInitFromMember)
  }
}

context(Raise<CommitError>)
internal fun ResolvedProposals.validateExternal() {
  getAll<ExternalInit>(ProposalType.ExternalInit).apply {
    if (isEmpty()) {
      raise(InvalidCommit.MissingExternalInit)
    } else if (size > 1) {
      raise(InvalidCommit.DoubleExternalInit)
    }
  }

  getAll<Remove>(ProposalType.Remove).apply {
    if (size > 1) raise(InvalidCommit.DoubleRemove)
  }

  getAll<PreSharedKey>(ProposalType.Psk).apply {
    checkDuplicates()
  }

  keys.find { it !in ProposalType.EXTERNAL_COMMIT }?.also {
    raise(InvalidCommit.InvalidExternalProposal(it))
  }
}

context(Raise<InvalidCommit.DoublePsk>)
private fun List<Pair<PreSharedKey, LeafIndex?>>.checkDuplicates() {
  asSequence().run {
    filterIndexed { idx, (psk, _) ->
      drop(idx + 1).any { it.first.pskId == psk.pskId }
    }.firstOrNull()
      ?.also { (psk, _) -> raise(InvalidCommit.DoublePsk(psk.pskId)) }
  }
}

internal inline fun <reified E : Proposal> ResolvedProposals.getAll(proposalType: ProposalType): List<Pair<E, LeafIndex?>> =
  getOrElse(proposalType, ::emptyList).map { (proposal, by) -> (proposal as E) to by }
