package com.github.traderjoe95.mls.protocol.group.resumption

import arrow.core.Tuple4
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.BranchError
import com.github.traderjoe95.mls.protocol.error.BranchJoinError
import com.github.traderjoe95.mls.protocol.error.ReInitError
import com.github.traderjoe95.mls.protocol.error.ReInitJoinError
import com.github.traderjoe95.mls.protocol.error.ResumptionJoinError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.newGroup
import com.github.traderjoe95.mls.protocol.group.prepareCommit
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafNodeIndices
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskUsage
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.message.PrivateMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.suspending.new

context(Raise<ReInitError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.reInitGroup(
  groupId: ULID? = null,
  protocolVersion: ProtocolVersion = this.settings.protocolVersion,
  cipherSuite: CipherSuite = this.cipherSuite,
  extensions: GroupContextExtensions = this.extensions,
  authenticatedData: ByteArray = byteArrayOf(),
  keepPastEpochs: UInt = 5U,
): Tuple4<GroupState, MlsMessage<PrivateMessage>, MlsMessage<Welcome>, GroupState> =
  ensureActive {
    val newGroupId = groupId ?: ULID.new()

    val (oldGroupAfterCommit, commitMsg, _) =
      prepareCommit(
        listOf(ReInit(newGroupId, protocolVersion, cipherSuite, extensions)),
        authenticatedData = authenticatedData,
      )

    val newGroupInitial =
      newGroup(
        cipherSuite,
        *extensions.toTypedArray(),
        protocolVersion = protocolVersion,
        groupId = newGroupId,
        keepPastEpochs = keepPastEpochs,
      )

    val keyPackages =
      getKeyPackages(
        protocolVersion,
        cipherSuite,
        authenticateCredentials(tree.leaves.filterNotNull()).bindAll(),
      ).values.bindAll()

    val (newGroupAfterCommit, _, welcome) =
      newGroupInitial.prepareCommit(
        keyPackages.map(::Add) + PreSharedKey(ResumptionPskId.reInit(oldGroupAfterCommit, cipherSuite)),
        inReInit = true,
      )

    return Tuple4(oldGroupAfterCommit, commitMsg, welcome!!, newGroupAfterCommit)
  }

context(Raise<BranchError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.branchGroup(
  leafIndices: List<LeafIndex>,
  groupId: ULID? = null,
  extensions: GroupContextExtensions = this.extensions,
  keepPastEpochs: UInt = 5U,
): Pair<GroupState, MlsMessage<Welcome>> =
  ensureActive {
    val newGroupId = groupId ?: ULID.new()

    val newGroupInitial =
      newGroup(
        cipherSuite,
        *extensions.toTypedArray(),
        protocolVersion = settings.protocolVersion,
        groupId = newGroupId,
        keepPastEpochs = keepPastEpochs,
      )

    val leafNodes =
      tree.leafNodeIndices
        .filter { it.leafIndex in leafIndices }
        .map { it to tree.leafNodeOrNull(it) }
        .partition { it.second != null }
        .let { (nonBlank, blank) ->
          if (blank.isNotEmpty()) raise(BranchError.BlankLeavesIncluded(blank.map { it.first.leafIndex }))

          nonBlank.map { it.second!! }
        }

    val keyPackages =
      getKeyPackages(
        settings.protocolVersion,
        cipherSuite,
        authenticateCredentials(leafNodes).bindAll(),
      ).values.bindAll()

    val (newGroupAfterCommit, _, welcome) =
      newGroupInitial.prepareCommit(
        keyPackages.map(::Add) + PreSharedKey(ResumptionPskId.branch(this)),
        inBranch = true,
      )

    return newGroupAfterCommit to welcome!!
  }

internal val PreSharedKeyId.isProtocolResumption: Boolean
  get() = this is ResumptionPskId && usage in ResumptionPskUsage.PROTOCOL_RESUMPTION

context(Raise<WelcomeJoinError>)
internal suspend fun <Identity : Any> ApplicationCtx<Identity>.validateResumption(
  groupContext: GroupContext,
  tree: RatchetTree,
  resumptionPsk: ResumptionPskId,
) = when (resumptionPsk.usage) {
  ResumptionPskUsage.ReInit -> validateReInit(groupContext, tree, resumptionPsk)
  ResumptionPskUsage.Branch -> validateBranch(groupContext, tree, resumptionPsk)
  else -> { // Nothing to validate
  }
}

context(Raise<ReInitJoinError>)
internal suspend fun <Identity : Any> ApplicationCtx<Identity>.validateReInit(
  groupContext: GroupContext,
  tree: RatchetTree,
  resumptionPsk: ResumptionPskId,
) {
  val evidence = getReInitEvidence(resumptionPsk.pskGroupId)

  if (evidence.currentEpoch != resumptionPsk.pskEpoch) {
    raise(ReInitJoinError.UnexpectedEpoch(evidence.currentEpoch, resumptionPsk.pskEpoch))
  }

  val reInit =
    evidence.lastCommitProposals
      .filterIsInstance<ReInit>()
      .firstOrNull()
      ?: raise(ReInitJoinError.NoReInitProposal)

  when {
    groupContext.groupId != reInit.groupId ->
      raise(ReInitJoinError.GroupIdMismatch(groupContext.groupId, reInit.groupId))

    groupContext.protocolVersion != reInit.protocolVersion ->
      raise(ResumptionJoinError.ProtocolVersionMismatch(groupContext.protocolVersion, reInit.protocolVersion))

    groupContext.cipherSuite != reInit.cipherSuite ->
      raise(ResumptionJoinError.CipherSuiteMismatch(groupContext.cipherSuite, reInit.cipherSuite))

    groupContext.extensions != reInit.extensions ->
      raise(ReInitJoinError.ExtensionsMismatch(groupContext.extensions, reInit.extensions))
  }

  tree.nonBlankLeafNodeIndices.forEach { leafNodeIdx ->
    val leafNode = tree[leafNodeIdx]!!.asLeaf

    evidence.members.find { isSameClient(leafNode.credential, it).bind() } ?: raise(ResumptionJoinError.NewMembersAdded)
  }

  if (tree.nonBlankLeafNodeIndices.size < evidence.members.size) {
    raise(ReInitJoinError.MembersMissing)
  }
}

context(Raise<BranchJoinError>)
internal suspend fun <Identity : Any> ApplicationCtx<Identity>.validateBranch(
  groupContext: GroupContext,
  tree: RatchetTree,
  resumptionPsk: ResumptionPskId,
) {
  val evidence = getBranchEvidence(resumptionPsk.pskGroupId)

  when {
    groupContext.protocolVersion != evidence.protocolVersion ->
      raise(ResumptionJoinError.ProtocolVersionMismatch(groupContext.protocolVersion, evidence.protocolVersion))

    groupContext.cipherSuite != evidence.cipherSuite ->
      raise(ResumptionJoinError.CipherSuiteMismatch(groupContext.cipherSuite, evidence.cipherSuite))
  }

  tree.nonBlankLeafNodeIndices.forEach { leafNodeIdx ->
    val leafNode = tree[leafNodeIdx]!!.asLeaf

    evidence.members.find { isSameClient(leafNode.credential, it).bind() } ?: raise(ResumptionJoinError.NewMembersAdded)
  }
}
