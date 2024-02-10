package com.github.traderjoe95.mls.protocol.group

import arrow.core.Tuple4
import arrow.core.getOrElse
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.crypto.calculatePskSecret
import com.github.traderjoe95.mls.protocol.error.CommitError
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.error.RecipientCommitError
import com.github.traderjoe95.mls.protocol.error.RecipientTreeUpdateError
import com.github.traderjoe95.mls.protocol.error.RemovedFromGroup
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.applyUpdate
import com.github.traderjoe95.mls.protocol.tree.applyUpdatePath
import com.github.traderjoe95.mls.protocol.tree.applyUpdatePathExternalJoin
import com.github.traderjoe95.mls.protocol.tree.filteredDirectPath
import com.github.traderjoe95.mls.protocol.tree.findEquivalentLeaf
import com.github.traderjoe95.mls.protocol.tree.lowestCommonAncestor
import com.github.traderjoe95.mls.protocol.tree.updatePath
import com.github.traderjoe95.mls.protocol.tree.validate
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ProposalOrRef
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.framing.message.EncryptedGroupSecrets
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupSecrets
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.framing.message.PrivateMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import com.github.traderjoe95.mls.protocol.util.zipWithIndex

context(Raise<SenderCommitError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.prepareCommit(
  proposals: List<ProposalOrRef>,
  authenticatedData: ByteArray = byteArrayOf(),
  inReInit: Boolean = false,
  inBranch: Boolean = false,
): Tuple4<GroupState, MlsMessage<PrivateMessage>, GroupInfo, MlsMessage<Welcome>?> =
  EncoderError.wrap {
    val (processedProposals, _) = proposals.validateMember(ownLeafIndex, inReInit, inBranch)

    val (preTree, updatedExtensions, pskSecrets, externalInitSecret, newMembers) = applyProposals(processedProposals)
    val pskSecret = EncoderError.wrap { pskSecrets.calculatePskSecret() }

    val (updatedTree, updatePath, pathSecrets) =
      preTree.updatePath(
        newMembers.map { it.first }.toSet(),
        ownLeafIndex,
        groupContext.withExtensions(updatedExtensions),
        signingKey,
      )

    val commitSecret = deriveSecret(pathSecrets.last(), "path")

    val commit =
      FramedContent(
        groupId,
        currentEpoch,
        Sender.member(ownLeafIndex),
        authenticatedData,
        Commit(proposals, updatePath),
      )
    val signature = commit.sign(WireFormat.MlsPrivateMessage, groupContext)

    val updatedGroupContext =
      groupContext.evolve(
        WireFormat.MlsPrivateMessage,
        commit,
        signature,
        updatedTree,
        newExtensions = updatedExtensions,
      )
    val (newKeySchedule, joinerSecret, welcomeSecret) =
      keySchedule.next(
        commitSecret,
        updatedGroupContext,
        updatedTree.leaves.uSize,
        pskSecret,
        externalInitSecret,
      )

    val confirmationTag = mac(newKeySchedule.confirmationKey, updatedGroupContext.confirmedTranscriptHash)
    val authData = FramedContent.AuthData(signature, confirmationTag)

    val memberContext =
      nextEpoch(
        commit.content,
        updatedGroupContext.withInterimTranscriptHash(confirmationTag),
        updatedTree,
        newKeySchedule,
      )
    val groupInfo = memberContext.createGroupInfo(authData.confirmationTag!!, settings.public)

    Tuple4(
      memberContext,
      MlsMessage.private(commit, authData),
      groupInfo,
      newMembers.createWelcome(groupInfo, updatedTree, pathSecrets, welcomeSecret, joinerSecret, pskSecrets),
    )
  }

context(Raise<RecipientCommitError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.processCommit(authenticatedCommit: AuthenticatedContent<Commit>): GroupState =
  EncoderError.wrap {
    val commit = authenticatedCommit.content
    val processedProposals = commit.content.validate(commit.sender)
    val updatePath = commit.content.updatePath

    val (preTree, updatedExtensions, pskSecrets, externalInitSecret, newMembers) =
      applyProposals(processedProposals)
    val pskSecret = EncoderError.wrap { pskSecrets.calculatePskSecret() }

    with(preTree) {
      if (ownLeafNodeIndex.isBlank) raise(RemovedFromGroup)
    }

    val (updatedTree, commitSecret) =
      updatePath.map { path ->
        preTree.applyCommitUpdatePath(
          groupContext.withExtensions(updatedExtensions),
          path,
          commit.sender,
          newMembers.map { it.first }.toSet(),
        )
      }.getOrElse { preTree to zeroesNh }

    val updatedGroupContext =
      groupContext.evolve(
        authenticatedCommit.wireFormat,
        commit,
        authenticatedCommit.signature,
        updatedTree,
        newExtensions = updatedExtensions,
      )
    val (newKeySchedule, _, _) =
      keySchedule.next(
        commitSecret,
        updatedGroupContext,
        updatedTree.leaves.uSize,
        pskSecret,
        externalInitSecret,
      )

    verifyMac(
      newKeySchedule.confirmationKey,
      updatedGroupContext.confirmedTranscriptHash,
      authenticatedCommit.confirmationTag!!,
    )

    nextEpoch(
      commit.content,
      updatedGroupContext.withInterimTranscriptHash(authenticatedCommit.confirmationTag),
      updatedTree,
      newKeySchedule,
    )
  }

context(GroupState, Raise<RecipientTreeUpdateError>)
private fun RatchetTree.applyCommitUpdatePath(
  groupContext: GroupContext,
  updatePath: UpdatePath,
  sender: Sender,
  excludeNewLeaves: Set<UInt>,
): Pair<RatchetTree, Secret> =
  if (sender.type == SenderType.Member) {
    applyUpdatePath(ownLeafIndex, groupContext, sender.index!!, updatePath, excludeNewLeaves)
  } else {
    applyUpdatePathExternalJoin(ownLeafIndex, groupContext, updatePath, excludeNewLeaves)
  }

context(GroupState, Raise<SenderCommitError>)
private fun List<Pair<UInt, KeyPackage>>.createWelcome(
  groupInfo: GroupInfo,
  newTree: RatchetTree,
  pathSecrets: List<Secret>,
  welcomeSecret: Secret,
  joinerSecret: Secret,
  pskSecrets: List<Pair<PreSharedKeyId, Secret>>,
): MlsMessage<Welcome>? =
  if (isEmpty()) {
    null
  } else {
    EncoderError.wrap {
      val welcomeNonce = expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), nonceLen).asNonce
      val welcomeKey = expandWithLabel(welcomeSecret, "key", byteArrayOf(), keyLen)

      val encryptedGroupInfo = encryptAead(welcomeKey, welcomeNonce, Aad.empty, GroupInfo.T.encode(groupInfo))

      val filteredDirectPath = newTree.filteredDirectPath(ownLeafNodeIndex)

      val encryptedGroupSecrets =
        map { (newLeaf, keyPackage) ->
          val commonAncestor = newTree.lowestCommonAncestor(ownLeafNodeIndex, newLeaf)
          val pathSecret = pathSecrets[filteredDirectPath.indexOf(commonAncestor)]

          val groupSecrets = GroupSecrets(joinerSecret, pathSecret, pskSecrets.map { it.first })

          EncryptedGroupSecrets(
            makeKeyPackageRef(keyPackage),
            encryptWithLabel(
              keyPackage.initKey,
              "Welcome",
              encryptedGroupInfo.value,
              GroupSecrets.T.encode(groupSecrets),
            ),
          )
        }

      MlsMessage.welcome(
        groupContext.cipherSuite,
        encryptedGroupSecrets,
        encryptedGroupInfo,
      )
    }
  }

context(Raise<CommitError>, ApplicationCtx<Identity>)
private suspend fun <Identity : Any> GroupState.applyProposals(proposals: List<Pair<Proposal, UInt?>>): ApplyProposalsResult {
  var tree = tree
  var extensions = extensions
  val pskSecrets = mutableListOf<Pair<PreSharedKeyId, Secret>>()
  var externalInitSecret: Secret? = null
  val newMembers = mutableListOf<Pair<UInt, KeyPackage>>()

  for ((proposal, generatedBy) in proposals) {
    when (proposal) {
      is GroupContextExtensions -> extensions = proposal.extensions

      is Update -> tree = tree.applyUpdate(proposal, generatedBy!!)
      is Remove -> tree -= proposal.removed
      is Add -> {
        val (updatedTree, newLeafIdx) = tree.insert(proposal.keyPackage.leafNode)
        tree = updatedTree

        newMembers.add(newLeafIdx * 2U to proposal.keyPackage)
      }

      is PreSharedKey ->
        pskSecrets += proposal.pskId to getPreSharedKey(proposal.pskId)

      is ExternalInit ->
        externalInitSecret = export(proposal.kemOutput, deriveKeyPair(keySchedule.externalSecret), "")

      is ReInit -> suspendGroup(groupId)
    }
  }

  return ApplyProposalsResult(tree, extensions, pskSecrets, externalInitSecret, newMembers)
}

data class ApplyProposalsResult(
  val updatedTree: RatchetTree,
  val nextExtensions: List<GroupContextExtension<*>>,
  val pskSecrets: List<Pair<PreSharedKeyId, Secret>>,
  val externalInitSecret: Secret?,
  val newMembers: List<Pair<UInt, KeyPackage>>,
)

context(GroupState, ApplicationCtx<Identity>, Raise<CommitError>)
private suspend fun <Identity : Any> Commit.validate(sender: Sender): List<Pair<Proposal, UInt?>> =
  when (sender.type) {
    SenderType.Member -> validateMember(sender.index!!)
    SenderType.NewMemberCommit -> validateExternal()
    else -> raise(InvalidCommit.BadCommitSender(sender.type))
  }.sortedBy {
    it.first.evaluationOrder()
  }

context(GroupState, ApplicationCtx<Identity>, Raise<CommitError>)
private suspend fun <Identity : Any> Commit.validateMember(leafIdx: UInt): List<Pair<Proposal, UInt?>> {
  if (updatePath.isNone() && proposals.isEmpty()) raise(InvalidCommit.MissingUpdatePath)

  return proposals.validateMember(leafIdx).let { (result, requireUpdatePath) ->
    if (requireUpdatePath && updatePath.isNone()) raise(InvalidCommit.MissingUpdatePath)

    updatePath.onSome {
      with(tree) {
        it.leafNode.validate(groupContext, leafIdx, LeafNodeSource.Commit)
      }
    }

    result
  }
}

context(GroupState, ApplicationCtx<Identity>, Raise<CommitError>)
private suspend fun <Identity : Any> List<ProposalOrRef>.validateMember(
  leafIdx: UInt,
  inReInit: Boolean = false,
  inBranch: Boolean = false,
): Pair<List<Pair<Proposal, UInt?>>, Boolean> {
  val leavesUpdatedOrRemoved = mutableSetOf<UInt>()
  val keyPackagesAdded = mutableSetOf<KeyPackage>()
  val reAdd = mutableMapOf<UInt, KeyPackage>()
  val pskIds = mutableSetOf<PreSharedKeyId>()
  var hasGroupCtxExt = false
  var requiresUpdatePath = false

  return map { proposalOrRef ->
    val (proposal, generatedBy) =
      when (proposalOrRef) {
        is Proposal -> proposalOrRef to leafIdx
        is Proposal.Ref -> getProposal(proposalOrRef)
      }

    if (proposal is Update) {
      if (leafIdx == generatedBy) raise(InvalidCommit.UpdateByCommitter)

      with(tree) {
        proposal.leafNode.validate(groupContext, generatedBy!!, LeafNodeSource.Update)
      }

      leavesUpdatedOrRemoved += generatedBy!!
    }

    if (proposal is Remove) {
      if (leafIdx == proposal.removed) raise(InvalidCommit.CommitterRemoved)
      if (leafIdx in leavesUpdatedOrRemoved) raise(InvalidCommit.AmbiguousUpdateOrRemove(leafIdx))

      leavesUpdatedOrRemoved += proposal.removed
      reAdd.remove(proposal.removed)
    }

    if (proposal is Add) {
      val keyPackage = proposal.keyPackage

      if (keyPackage.cipherSuite != cipherSuite) {
        raise(InvalidCommit.KeyPackageInvalidCipherSuite(keyPackage.cipherSuite, cipherSuite))
      }

      if (keyPackagesAdded.any { it isSameClientAs keyPackage }) {
        raise(InvalidCommit.DoubleAdd(keyPackage))
      }

      tree.findEquivalentLeaf(keyPackage)?.let {
        if (it !in leavesUpdatedOrRemoved) reAdd[it] = keyPackage
      }

      with(tree) {
        keyPackage.leafNode.validate(
          groupContext,
          firstBlankLeaf ?: (leafIndices.last + 2U),
          LeafNodeSource.KeyPackage,
        )
      }

      keyPackage.verifySignature()
      keyPackagesAdded.add(keyPackage)
    }

    if (proposal is PreSharedKey) {
      val pskId = proposal.pskId
      if (pskId in pskIds) raise(InvalidCommit.DoublePsk(proposal.pskId))
      pskId.validate(inReInit, inBranch)

      pskIds += proposal.pskId
    }

    if (proposal is GroupContextExtensions) {
      if (hasGroupCtxExt) raise(InvalidCommit.AmbiguousGroupCtxExtensions)

      // Verify that all members support the RequiredCapabilities, if present
      proposal.extension<RequiredCapabilities>()?.let { requiredCapabilities ->
        tree.leaves
          .zipWithIndex()
          .mapNotNull { (maybeLeaf, idx) -> maybeLeaf?.let { it.node to idx.toUInt() } }
          .filter { (leaf, _) -> requiredCapabilities.isCompatible(leaf.capabilities) }
          .onEach { (leaf, leafIdx) ->
            raise(LeafNodeCheckError.UnsupportedCapabilities(leafIdx, requiredCapabilities, leaf.capabilities))
          }
      }

      hasGroupCtxExt = true
    }

    if (proposal is ReInit && size > 1) raise(InvalidCommit.ReInitMustBeSingle)
    if (proposal is ExternalInit) raise(InvalidCommit.ExternalInitFromMember)

    requiresUpdatePath = requiresUpdatePath || proposal.requiresPath

    proposal to generatedBy
  }.also {
    if (reAdd.isNotEmpty()) raise(InvalidCommit.ReAdd(reAdd.values.first()))
  } to requiresUpdatePath
}

context(GroupState, ApplicationCtx<Identity>, Raise<CommitError>)
private suspend fun <Identity : Any> Commit.validateExternal(): List<Pair<Proposal, UInt?>> {
  var hasExternalInit = false
  var hasRemove = false
  val pskIds = mutableSetOf<PreSharedKeyId>()

  val path = updatePath.getOrElse { raise(InvalidCommit.MissingUpdatePath) }

  with(tree) {
    path.leafNode.validate(groupContext, tree.firstBlankLeaf ?: (tree.leafIndices.last + 2U), LeafNodeSource.Commit)
  }

  return proposals.map { proposalOrRef ->
    val (proposal, generatedBy) =
      when (proposalOrRef) {
        is Proposal -> proposalOrRef to null
        is Proposal.Ref -> raise(InvalidCommit.NoProposalRefAllowed)
      }

    when (proposal) {
      is ExternalInit -> {
        if (hasExternalInit) raise(InvalidCommit.DoubleExternalInit)

        hasExternalInit = true
      }

      is PreSharedKey -> {
        if (proposal.pskId in pskIds) raise(InvalidCommit.DoublePsk(proposal.pskId))
        proposal.pskId.validate(inReInit = false, inBranch = false)

        pskIds += proposal.pskId
      }

      is Remove -> {
        if (hasRemove) raise(InvalidCommit.DoubleRemove)

        tree.findEquivalentLeaf(path.leafNode)
          ?.takeIf { it == proposal.removed }
          ?: raise(InvalidCommit.UnauthorizedExternalRemove(proposal.removed))

        hasRemove = true
      }

      else -> raise(InvalidCommit.InvalidExternalProposal(proposal.type))
    }

    proposal to generatedBy
  }.also {
    if (!hasExternalInit) raise(InvalidCommit.MissingExternalInit)
  }
}
