package com.github.traderjoe95.mls.protocol.group.resumption

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.BranchError
import com.github.traderjoe95.mls.protocol.error.BranchJoinError
import com.github.traderjoe95.mls.protocol.error.ReInitError
import com.github.traderjoe95.mls.protocol.error.ReInitJoinError
import com.github.traderjoe95.mls.protocol.error.ResumptionJoinError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.PrepareCommitResult
import com.github.traderjoe95.mls.protocol.group.newGroup
import com.github.traderjoe95.mls.protocol.group.prepareCommit
import com.github.traderjoe95.mls.protocol.message.GroupMessage
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.service.DeliveryService
import com.github.traderjoe95.mls.protocol.service.authenticateCredentials
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTreeOps
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafNodeIndices
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskUsage
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

context(Raise<ReInitError>, AuthenticationService<Identity>)
suspend fun <Identity : Any> GroupState.Active.reInitGroup(
  groupId: GroupId? = null,
  protocolVersion: ProtocolVersion = this.protocolVersion,
  cipherSuite: CipherSuite = this.cipherSuite,
  extensions: GroupContextExtensions = this.extensions,
  authenticatedData: ByteArray = byteArrayOf(),
  usePrivateMessage: Boolean = false,
): Pair<GroupState.Suspended, MlsMessage<GroupMessage<*>>> {
  val newGroupId = groupId ?: GroupId.new()

  val oldGroupResult =
    prepareCommit(
      listOf(ReInit(newGroupId, protocolVersion, cipherSuite, extensions)),
      authenticatedData = authenticatedData,
      usePrivateMessage = usePrivateMessage,
    )
  val suspended = oldGroupResult.newGroupState as GroupState.Suspended

  return suspended to oldGroupResult.commit
}

context(Raise<ReInitError>, AuthenticationService<Identity>, DeliveryService<Identity>)
suspend fun <Identity : Any> GroupState.Suspended.createWelcome(
  ownKeyPackage: KeyPackage.Private,
): Pair<GroupState, List<PrepareCommitResult.WelcomeMessage>> =
  createWelcome(
    ownKeyPackage,
    getKeyPackages(
      reInit.protocolVersion,
      reInit.cipherSuite,
      authenticateCredentials(
        tree.leaves
          .filterIndexed { idx, _ -> idx != leafIndex.value.toInt() }
          .filterNotNull(),
      ).bindAll(),
    ).values.bindAll(),
  )

context(Raise<ReInitError>, AuthenticationService<Identity>)
suspend fun <Identity : Any> GroupState.Suspended.createWelcome(
  ownKeyPackage: KeyPackage.Private,
  otherKeyPackages: List<KeyPackage>,
): Pair<GroupState, List<PrepareCommitResult.WelcomeMessage>> {
  val newGroupInitial =
    newGroup(
      ownKeyPackage,
      *reInit.extensions.toTypedArray(),
      protocolVersion = reInit.protocolVersion,
      cipherSuite = reInit.cipherSuite,
      groupId = reInit.groupId,
    )

  val (newGroup, _, newMemberWelcome) =
    newGroupInitial.prepareCommit(
      otherKeyPackages.map(::Add) + PreSharedKey(ResumptionPskId.reInit(this, reInit.cipherSuite)),
      inReInit = true,
      psks = this,
    )

  return newGroup to newMemberWelcome
}

context(Raise<BranchError>, AuthenticationService<Identity>, DeliveryService<Identity>)
suspend fun <Identity : Any> GroupState.Active.branchGroup(
  ownKeyPackage: KeyPackage.Private,
  otherMemberLeafIndices: List<LeafIndex>,
  groupId: GroupId? = null,
  extensions: GroupContextExtensions = this.extensions,
): BranchResult {
  val leafNodes =
    tree.leafNodeIndices
      .filter { it.leafIndex in (otherMemberLeafIndices - leafIndex) }
      .map { it to tree.leafNodeOrNull(it) }
      .partition { it.second != null }
      .let { (nonBlank, blank) ->
        if (blank.isNotEmpty()) raise(BranchError.BlankLeavesIncluded(blank.map { it.first.leafIndex }))

        nonBlank.map { it.second!! }
      }

  val keyPackages =
    getKeyPackages(
      protocolVersion,
      cipherSuite,
      authenticateCredentials(leafNodes).bindAll(),
    ).values.bindAll()

  return branchGroup(
    ownKeyPackage,
    keyPackages,
    groupId,
    extensions,
  )
}

context(Raise<BranchError>, AuthenticationService<Identity>)
suspend fun <Identity : Any> GroupState.Active.branchGroup(
  ownKeyPackage: KeyPackage.Private,
  otherMemberKeyPackages: List<KeyPackage>,
  groupId: GroupId? = null,
  extensions: GroupContextExtensions = this.extensions,
): BranchResult {
  val newGroupInitial =
    newGroup(
      ownKeyPackage,
      *extensions.toTypedArray(),
      groupId = groupId,
    )

  val (newGroupAfterCommit, _, welcome) =
    newGroupInitial.prepareCommit(
      otherMemberKeyPackages.map(::Add) + PreSharedKey(ResumptionPskId.branch(this)),
      inBranch = true,
      psks = this,
    )

  return BranchResult(newGroupAfterCommit, welcome)
}

internal val PreSharedKeyId.isProtocolResumption: Boolean
  get() = this is ResumptionPskId && usage in ResumptionPskUsage.PROTOCOL_RESUMPTION

context(Raise<WelcomeJoinError>, AuthenticationService<Identity>)
internal suspend fun <Identity : Any> validateResumption(
  groupContext: GroupContext,
  tree: RatchetTreeOps,
  resumptionPsk: ResumptionPskId,
  resumptionGroup: GroupState,
) = when (resumptionPsk.usage) {
  ResumptionPskUsage.ReInit ->
    validateReInit(
      (resumptionGroup as GroupState.Suspended),
      groupContext,
      tree,
      resumptionPsk,
    )

  ResumptionPskUsage.Branch -> validateBranch(resumptionGroup, groupContext, tree)
  else -> { // Nothing to validate
  }
}

context(Raise<ReInitJoinError>, AuthenticationService<Identity>)
internal suspend fun <Identity : Any> validateReInit(
  suspended: GroupState.Suspended,
  groupContext: GroupContext,
  tree: RatchetTreeOps,
  resumptionPsk: ResumptionPskId,
) {
  if (suspended.epoch != resumptionPsk.pskEpoch) {
    raise(ReInitJoinError.UnexpectedEpoch(suspended.epoch, resumptionPsk.pskEpoch))
  }

  when {
    groupContext.groupId neq suspended.reInit.groupId ->
      raise(ReInitJoinError.GroupIdMismatch(groupContext.groupId, suspended.reInit.groupId))

    groupContext.protocolVersion != suspended.reInit.protocolVersion ->
      raise(
        ResumptionJoinError.ProtocolVersionMismatch(
          groupContext.protocolVersion,
          suspended.reInit.protocolVersion,
        ),
      )

    groupContext.cipherSuite != suspended.reInit.cipherSuite ->
      raise(
        ResumptionJoinError.CipherSuiteMismatch(
          groupContext.cipherSuite,
          suspended.reInit.cipherSuite,
        ),
      )

    groupContext.extensions != suspended.reInit.extensions ->
      raise(
        ReInitJoinError.ExtensionsMismatch(
          groupContext.extensions,
          suspended.reInit.extensions,
        ),
      )
  }

  tree.nonBlankLeafNodeIndices.forEach { leafNodeIdx ->
    val leafNode = tree[leafNodeIdx]!!.asLeaf

    suspended.tree.leaves
      .filterNotNull()
      .find { isSameClient(leafNode.credential, it.credential).bind() }
      ?: raise(ResumptionJoinError.NewMembersAdded)
  }

  if (tree.nonBlankLeafNodeIndices.size < suspended.tree.nonBlankLeafNodeIndices.size) {
    raise(ReInitJoinError.MembersMissing)
  }
}

context(Raise<BranchJoinError>, AuthenticationService<Identity>)
internal suspend fun <Identity : Any> validateBranch(
  originalGroup: GroupState,
  groupContext: GroupContext,
  tree: RatchetTreeOps,
) {
  when {
    groupContext.protocolVersion != originalGroup.protocolVersion ->
      raise(ResumptionJoinError.ProtocolVersionMismatch(groupContext.protocolVersion, originalGroup.protocolVersion))

    groupContext.cipherSuite != originalGroup.cipherSuite ->
      raise(ResumptionJoinError.CipherSuiteMismatch(groupContext.cipherSuite, originalGroup.cipherSuite))
  }

  tree.nonBlankLeafNodeIndices.forEach { leafNodeIdx ->
    val leafNode = tree[leafNodeIdx]!!.asLeaf

    originalGroup.tree.leaves
      .filterNotNull()
      .find { isSameClient(leafNode.credential, it.credential).bind() }
      ?: raise(ResumptionJoinError.NewMembersAdded)
  }
}
