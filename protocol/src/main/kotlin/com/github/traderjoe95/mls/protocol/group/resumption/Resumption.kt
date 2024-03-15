package com.github.traderjoe95.mls.protocol.group.resumption

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
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
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MessageOptions
import com.github.traderjoe95.mls.protocol.message.UsePublicMessage
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskUsage
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.service.DeliveryService
import com.github.traderjoe95.mls.protocol.service.authenticateCredentials
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTreeOps
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafNodeIndices
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

suspend fun <Identity : Any> GroupState.Active.triggerReInit(
  authenticationService: AuthenticationService<Identity>,
  groupId: GroupId? = null,
  protocolVersion: ProtocolVersion = this.protocolVersion,
  cipherSuite: CipherSuite = this.cipherSuite,
  extensions: GroupContextExtensions = this.extensions,
  authenticatedData: ByteArray = byteArrayOf(),
  messageOptions: MessageOptions = UsePublicMessage,
): Either<ReInitError, TriggerReInitResult> =
  either {
    val newGroupId = groupId ?: GroupId.new()

    val oldGroupResult =
      prepareCommit(
        listOf(ReInit(newGroupId, protocolVersion, cipherSuite, extensions)),
        authenticationService,
        authenticatedData = authenticatedData,
        messageOptions = messageOptions,
      ).bind()

    TriggerReInitResult(oldGroupResult.newGroupState.coerceSuspended(), oldGroupResult.commit)
  }

suspend fun <Identity : Any> GroupState.Suspended.resumeReInit(
  ownKeyPackage: KeyPackage.Private,
  authenticationService: AuthenticationService<Identity>,
  deliveryService: DeliveryService<Identity>,
  inlineTree: Boolean = true,
  forcePath: Boolean = false,
): Either<ReInitError, ResumptionResult> =
  either {
    resumeReInit(
      ownKeyPackage,
      deliveryService.getKeyPackages(
        reInit.protocolVersion,
        reInit.cipherSuite,
        authenticationService.authenticateCredentials(
          tree.leaves
            .filterIndexed { idx, _ -> idx != leafIndex.value.toInt() }
            .filterNotNull(),
        ).bindAll(),
      ).values.bindAll(),
      authenticationService,
      inlineTree,
      forcePath,
    ).bind()
  }

suspend fun <Identity : Any> GroupState.Suspended.resumeReInit(
  ownKeyPackage: KeyPackage.Private,
  otherKeyPackages: List<KeyPackage>,
  authenticationService: AuthenticationService<Identity>,
  inlineTree: Boolean = true,
  forcePath: Boolean = false,
): Either<ReInitError, ResumptionResult> =
  either {
    val newGroupInitial =
      newGroup(
        ownKeyPackage,
        *reInit.extensions.map { it as GroupContextExtension<*> }.toTypedArray(),
        protocolVersion = reInit.protocolVersion,
        cipherSuite = reInit.cipherSuite,
        groupId = reInit.groupId,
      ).bind()

    val (newGroup, _, newMemberWelcome) =
      newGroupInitial.prepareCommit(
        otherKeyPackages.map(::Add) + PreSharedKey(ResumptionPskId.reInit(this@resumeReInit, reInit.cipherSuite)),
        authenticationService,
        inReInit = true,
        psks = this@resumeReInit,
        inlineTree = inlineTree,
        forcePath = forcePath,
      ).bind()

    ResumptionResult(newGroup.coerceActive(), newMemberWelcome)
  }

suspend fun <Identity : Any> GroupState.Active.branchGroup(
  ownKeyPackage: KeyPackage.Private,
  otherMemberLeafIndices: List<LeafIndex>,
  authenticationService: AuthenticationService<Identity>,
  deliveryService: DeliveryService<Identity>,
  groupId: GroupId? = null,
  extensions: GroupContextExtensions = this.extensions,
  inlineTree: Boolean = true,
  forcePath: Boolean = false,
): Either<BranchError, ResumptionResult> =
  either {
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
      deliveryService.getKeyPackages(
        protocolVersion,
        cipherSuite,
        authenticationService.authenticateCredentials(leafNodes).bindAll(),
      ).values.bindAll()

    branchGroup(
      ownKeyPackage,
      keyPackages,
      authenticationService,
      groupId,
      extensions,
      inlineTree,
      forcePath,
    ).bind()
  }

suspend fun <Identity : Any> GroupState.Active.branchGroup(
  ownKeyPackage: KeyPackage.Private,
  otherMemberKeyPackages: List<KeyPackage>,
  authenticationService: AuthenticationService<Identity>,
  groupId: GroupId? = null,
  extensions: GroupContextExtensions = this.extensions,
  inlineTree: Boolean = true,
  forcePath: Boolean = false,
): Either<BranchError, ResumptionResult> =
  either {
    val newGroupInitial =
      newGroup(
        ownKeyPackage,
        *extensions.toTypedArray(),
        groupId = groupId,
      ).bind()

    val (newGroupAfterCommit, _, welcome) =
      newGroupInitial.prepareCommit(
        otherMemberKeyPackages.map(::Add) + PreSharedKey(ResumptionPskId.branch(this@branchGroup)),
        authenticationService,
        inBranch = true,
        psks = this@branchGroup,
        inlineTree = inlineTree,
        forcePath = forcePath,
      ).bind()

    ResumptionResult(newGroupAfterCommit.coerceActive(), welcome)
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
          suspended.reInit.extensions.map { it as GroupContextExtension<*> },
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
