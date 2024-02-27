package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import arrow.core.raise.nullable
import com.github.traderjoe95.mls.protocol.error.CommitError
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.findEquivalentLeaf
import com.github.traderjoe95.mls.protocol.tree.validate
import com.github.traderjoe95.mls.protocol.tree.zipWithLeafIndex
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource

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

  keys.find { it !in ProposalType.EXTERNAL }?.also {
    raise(InvalidCommit.InvalidExternalProposal(it))
  }
}

context(Raise<InvalidCommit.DoublePsk>)
private fun List<Pair<PreSharedKey, LeafIndex?>>.checkDuplicates() {
  filterIndexed { idx, (psk, _) ->
    subList(idx + 1, size).any { it.first.pskId == psk.pskId }
  }.firstOrNull()
    ?.also { (psk, _) -> raise(InvalidCommit.DoublePsk(psk.pskId)) }
}

context(Raise<CommitError>, GroupState, AuthenticationService<Identity>)
suspend fun <Identity : Any> Add.validate(currentTree: RatchetTree) {
  if (keyPackage.version != protocolVersion) {
    raise(InvalidCommit.IncompatibleProtocolVersion(keyPackage.version, protocolVersion))
  }

  if (keyPackage.cipherSuite != cipherSuite) {
    raise(InvalidCommit.IncompatibleCipherSuite(keyPackage.cipherSuite, cipherSuite))
  }

  currentTree.findEquivalentLeaf(keyPackage.leafNode)?.also { raise(InvalidCommit.AlreadyMember(keyPackage, it)) }

  keyPackage.leafNode.validate(
    currentTree,
    groupContext,
    currentTree.firstBlankLeaf ?: (currentTree.leafNodeIndices.last + 2U).leafIndex,
    LeafNodeSource.KeyPackage,
  )

  keyPackage.verifySignature()

  if (keyPackage.initKey.eq(keyPackage.leafNode.encryptionKey)) {
    raise(InvalidCommit.InitKeyReuseAsEncryptionKey(keyPackage))
  }
}

context(Raise<CommitError>, GroupState.Active, AuthenticationService<Identity>)
internal suspend fun <Identity : Any> Update.validate(
  currentTree: RatchetTree,
  generatedBy: LeafIndex,
) {
  leafNode.validate(currentTree, groupContext, generatedBy, LeafNodeSource.Update)
}

context(Raise<CommitError>, AuthenticationService<Identity>)
internal suspend fun <Identity : Any> Remove.validate(
  currentTree: RatchetTree,
  expectedClient: Credential?,
) {
  if (currentTree[removed] == null) raise(InvalidCommit.BlankLeafRemoved(removed))

  expectedClient?.also { expected ->
    if (!isSameClient(expected, currentTree.leafNode(removed).credential).bind()) {
      raise(InvalidCommit.UnauthorizedExternalRemove(removed))
    }
  }
}

context(Raise<CommitError>, GroupState)
suspend fun PreSharedKey.validateAndLoad(
  inReInit: Boolean,
  inBranch: Boolean,
  psks: PskLookup,
): Secret {
  pskId.validate(inReInit, inBranch)
  return psks.getPreSharedKey(pskId)
}

context(Raise<CommitError>, GroupState)
internal fun ReInit.validate() {
  if (protocolVersion < this@GroupState.protocolVersion) {
    raise(InvalidCommit.ReInitDowngrade(this@GroupState.protocolVersion, protocolVersion))
  }

  extensions.find { it !is GroupContextExtension<*> }?.also {
    raise(
      InvalidCommit.UnexpectedExtension(
        "GroupContext",
        it.extensionType?.toString() ?: it.type.toString(),
      ),
    )
  }
}

context(Raise<CommitError>, GroupState)
internal fun GroupContextExtensions.validate(
  currentTree: RatchetTree,
  removed: Set<LeafIndex>,
) {
  extension<RequiredCapabilities>()?.let { required ->
    currentTree.leaves
      .zipWithLeafIndex()
      .mapNotNull {
        nullable { it.first.bind() to it.second }
      }
      .filterNot { (leaf, leafIdx) -> leafIdx in removed || required.isCompatible(leaf.capabilities) }
      .onEach { (leaf, leafIdx) ->
        raise(LeafNodeCheckError.UnsupportedCapabilities(leafIdx, required, leaf.capabilities))
      }
  }
}

internal inline fun <reified E : Proposal> ResolvedProposals.getAll(proposalType: ProposalType): List<Pair<E, LeafIndex?>> =
  getOrElse(proposalType, ::emptyList).map { (proposal, by) -> (proposal as E) to by }
