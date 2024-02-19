package com.github.traderjoe95.mls.protocol.group

import arrow.core.None
import arrow.core.Option
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.nullable
import arrow.core.toOption
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.CommitError
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.RecipientCommitError
import com.github.traderjoe95.mls.protocol.error.RecipientTreeUpdateError
import com.github.traderjoe95.mls.protocol.error.RemovedFromGroup
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.applyUpdatePath
import com.github.traderjoe95.mls.protocol.tree.applyUpdatePathExternalJoin
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.lowestCommonAncestor
import com.github.traderjoe95.mls.protocol.tree.validate
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.PskLabel
import com.github.traderjoe95.mls.protocol.types.crypto.PskLabel.Companion.encodeUnsafe
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
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.framing.message.EncryptedGroupSecrets
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupSecrets
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupSecrets.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.framing.message.PathSecret
import com.github.traderjoe95.mls.protocol.types.framing.message.PrivateMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import de.traderjoe.ulid.ULID

context(Raise<SenderCommitError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.prepareCommit(
  proposals: List<ProposalOrRef>,
  authenticatedData: ByteArray = byteArrayOf(),
  inReInit: Boolean = false,
  inBranch: Boolean = false,
  createPublicGroupInfo: Boolean = false,
): Triple<GroupState, MlsMessage<PrivateMessage>, MlsMessage<Welcome>?> =
  ensureActive {
    val proposalResult = processProposals(proposals, None, ownLeafIndex, inReInit, inBranch)

    val (updatedTree, updatePath, pathSecrets) =
      if (proposalResult.updatePathRequired) {
        createUpdatePath(
          (proposalResult.updatedTree ?: tree),
          proposalResult.newMemberLeafIndices(),
          groupContext.withExtensions((proposalResult as? ProcessProposalsResult.CommitByMember)?.extensions),
          signingKey,
        )
      } else {
        Triple((proposalResult.updatedTree ?: tree), null, listOf())
      }

    val commitSecret = nullable { deriveSecret(pathSecrets.lastOrNull().bind(), "path") } ?: zeroesNh

    val commit =
      FramedContent(
        groupId,
        currentEpoch,
        Sender.member(ownLeafIndex),
        authenticatedData,
        Commit(proposals, updatePath.toOption()),
      )
    val signature = commit.sign(WireFormat.MlsPrivateMessage, groupContext)

    val updatedGroupContext =
      groupContext.evolve(
        WireFormat.MlsPrivateMessage,
        commit,
        signature,
        updatedTree,
        newExtensions = (proposalResult as? ProcessProposalsResult.CommitByMember)?.extensions,
      )
    val (newKeySchedule, joinerSecret, welcomeSecret) =
      keySchedule.next(
        commitSecret,
        updatedGroupContext,
        updatedTree.leaves.uSize,
        proposalResult.pskSecret,
        (proposalResult as? ProcessProposalsResult.ExternalJoin)?.externalInitSecret,
      )

    val confirmationTag = mac(newKeySchedule.confirmationKey, updatedGroupContext.confirmedTranscriptHash)
    val authData = FramedContent.AuthData(signature, confirmationTag)

    val updatedGroupState =
      proposalResult.createNextEpochState(
        commit.content,
        updatedGroupContext.withInterimTranscriptHash(confirmationTag),
        updatedTree,
        newKeySchedule,
      )
    val groupInfo = updatedGroupState.groupInfo(createPublicGroupInfo)

    Triple(
      updatedGroupState,
      MlsMessage.private(commit, authData),
      proposalResult.welcomeTo
        ?.createWelcome(
          groupInfo,
          updatedTree,
          pathSecrets,
          welcomeSecret,
          joinerSecret,
          proposalResult.pskIds,
        ),
    )
  }

context(Raise<RecipientCommitError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.processCommit(authenticatedCommit: AuthenticatedContent<Commit>): GroupState =
  ensureActive {
    val commit = authenticatedCommit.content
    val proposalResult = commit.content.validateAndApply(commit.sender)
    val updatePath = commit.content.updatePath

    val preTree = proposalResult.updatedTree ?: tree

    with(preTree) {
      if (ownLeafIndex.isBlank) raise(RemovedFromGroup)
    }

    val (updatedTree, commitSecret) =
      updatePath.map { path ->
        preTree.applyCommitUpdatePath(
          groupContext.withExtensions((proposalResult as? ProcessProposalsResult.CommitByMember)?.extensions),
          path,
          commit.sender,
          proposalResult.newMemberLeafIndices(),
        )
      }.getOrElse { preTree to zeroesNh }

    val updatedGroupContext =
      groupContext.evolve(
        authenticatedCommit.wireFormat,
        commit,
        authenticatedCommit.signature,
        updatedTree,
        newExtensions = (proposalResult as? ProcessProposalsResult.CommitByMember)?.extensions,
      )
    val (newKeySchedule, _, _) =
      keySchedule.next(
        commitSecret,
        updatedGroupContext,
        updatedTree.leaves.uSize,
        proposalResult.pskSecret,
        (proposalResult as? ProcessProposalsResult.ExternalJoin)?.externalInitSecret,
      )

    verifyMac(
      newKeySchedule.confirmationKey,
      updatedGroupContext.confirmedTranscriptHash,
      authenticatedCommit.confirmationTag!!,
    )

    proposalResult.createNextEpochState(
      commit.content,
      updatedGroupContext.withInterimTranscriptHash(authenticatedCommit.confirmationTag),
      updatedTree,
      newKeySchedule,
    )
  }

context(ActiveGroupState, ApplicationCtx<Identity>, Raise<CommitError>)
private suspend fun <Identity : Any> Commit.validateAndApply(sender: Sender): ProcessProposalsResult =
  processProposals(
    proposals,
    updatePath,
    when (sender.type) {
      SenderType.Member -> sender.index!!
      SenderType.NewMemberCommit -> null
      else -> raise(InvalidCommit.BadCommitSender(sender.type))
    },
    inReInit = false,
    inBranch = false,
  ).also { result ->
    if (result.updatePathRequired && updatePath.isNone()) raise(InvalidCommit.MissingUpdatePath)

    updatePath.onSome {
      it.leafNode.validate(
        tree,
        groupContext,
        sender.index
          ?: tree.firstBlankLeaf
          ?: (tree.leafNodeIndices.last + 2U).leafIndex,
        LeafNodeSource.Commit,
      )
    }
  }

context(GroupState)
private fun ProcessProposalsResult.newMemberLeafIndices(): Set<LeafIndex> =
  when (this) {
    is ProcessProposalsResult.CommitByMember -> welcomeTo.map { it.first }.toSet()
    is ProcessProposalsResult.ExternalJoin -> setOf(tree.firstBlankLeaf ?: (tree.leafNodeIndices.last + 2U).leafIndex)
    is ProcessProposalsResult.ReInitCommit -> setOf()
  }

context(ActiveGroupState, Raise<RecipientTreeUpdateError>)
private fun RatchetTree.applyCommitUpdatePath(
  groupContext: GroupContext,
  updatePath: UpdatePath,
  sender: Sender,
  excludeNewLeaves: Set<LeafIndex>,
): Pair<RatchetTree, Secret> =
  if (sender.type == SenderType.Member) {
    applyUpdatePath(this, groupContext, sender.index!!, updatePath, excludeNewLeaves)
  } else {
    applyUpdatePathExternalJoin(groupContext, updatePath, excludeNewLeaves)
  }

context(ActiveGroupState, Raise<SenderCommitError>)
private fun List<Pair<LeafIndex, KeyPackage>>.createWelcome(
  groupInfo: GroupInfo,
  newTree: RatchetTree,
  pathSecrets: List<Secret>,
  welcomeSecret: Secret,
  joinerSecret: Secret,
  pskIds: List<PreSharedKeyId>,
): MlsMessage<Welcome>? =
  if (isEmpty()) {
    null
  } else {
    val welcomeNonce = expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), nonceLen).asNonce
    val welcomeKey = expandWithLabel(welcomeSecret, "key", byteArrayOf(), keyLen)

    val encryptedGroupInfo = encryptAead(welcomeKey, welcomeNonce, Aad.empty, groupInfo.encodeUnsafe())

    val filteredPath = newTree.filteredDirectPath(ownLeafIndex)

    val encryptedGroupSecrets =
      map { (newLeaf, keyPackage) ->
        val commonAncestor = lowestCommonAncestor(ownLeafIndex, newLeaf)
        val pathSecret = pathSecrets.getOrNull(filteredPath.indexOf(commonAncestor)).toOption().map(::PathSecret)

        val groupSecrets = GroupSecrets(joinerSecret, pathSecret, pskIds)

        EncryptedGroupSecrets(
          makeKeyPackageRef(keyPackage),
          encryptWithLabel(
            keyPackage.initKey,
            "Welcome",
            encryptedGroupInfo.value,
            groupSecrets.encodeUnsafe(),
          ),
        )
      }

    MlsMessage.welcome(
      groupContext.cipherSuite,
      encryptedGroupSecrets,
      encryptedGroupInfo,
    )
  }

context(Raise<CommitError>, ApplicationCtx<Identity>)
private suspend fun <Identity : Any> ActiveGroupState.processProposals(
  proposals: List<ProposalOrRef>,
  updatePath: Option<UpdatePath>,
  committerLeafIdx: LeafIndex?,
  inReInit: Boolean = false,
  inBranch: Boolean = false,
): ProcessProposalsResult {
  val resolved: ResolvedProposals = mutableMapOf()

  proposals.forEach { proposalOrRef ->
    when (proposalOrRef) {
      is Proposal ->
        resolved.compute(proposalOrRef.type) { _, current ->
          (current ?: listOf()) + (proposalOrRef to committerLeafIdx)
        }

      is Proposal.Ref ->
        if (committerLeafIdx == null) {
          raise(InvalidCommit.NoProposalRefAllowed)
        } else {
          getProposal(proposalOrRef)
        }
    }
  }

  if (committerLeafIdx == null) {
    resolved.validateExternal()
  } else {
    resolved.validateMember(committerLeafIdx)
  }

  var requiresUpdatePath = proposals.isEmpty()
  var updatedTree = tree
  var extensions: List<GroupContextExtension<*>>? = null
  val welcomeTo = mutableListOf<Pair<LeafIndex, KeyPackage>>()

  var pskSecret = zeroesNh
  var pskIndex = 0
  val pskCount = resolved[ProposalType.Psk]?.size ?: 0
  val pskIds = mutableListOf<PreSharedKeyId>()

  ProposalType.ORDER.asSequence()
    .flatMap { resolved.getAll<Proposal>(it).asSequence() }
    .forEach { (proposal, from) ->
      when (proposal) {
        is GroupContextExtensions -> {
          proposal.validate(updatedTree, resolved.getAll<Remove>(ProposalType.Remove).map { it.first.removed }.toSet())

          extensions = proposal.extensions
        }

        is Update -> {
          proposal.validate(updatedTree, from!!)

          updatedTree = updatedTree.update(from, proposal.leafNode)
          requiresUpdatePath = true
        }

        is Remove -> {
          proposal.validate(
            updatedTree,
            updatePath.getOrNull()?.leafNode?.credential?.takeIf { committerLeafIdx == null },
          )

          updatedTree = updatedTree.remove(proposal.removed)
          requiresUpdatePath = true
        }

        is Add -> {
          proposal.validate(updatedTree)

          val (treeWithNewMember, newMemberLeaf) = updatedTree.insert(proposal.keyPackage.leafNode)

          updatedTree = treeWithNewMember
          welcomeTo.add(newMemberLeaf to proposal.keyPackage)
        }

        is PreSharedKey -> {
          val psk = proposal.validateAndLoad(inReInit, inBranch)

          val pskInput =
            expandWithLabel(
              extract(zeroesNh.key, psk),
              "derivedPsk",
              PskLabel(proposal.pskId, pskIndex++, pskCount).encodeUnsafe(),
              hashLen,
            )

          pskSecret = extract(pskInput.key, pskSecret)
          pskIds.add(proposal.pskId)
        }

        is ExternalInit ->
          return ProcessProposalsResult.ExternalJoin(
            externalInitSecret = export(proposal.kemOutput, deriveKeyPair(keySchedule.externalSecret), ""),
            pskSecret,
            updatedTree,
          )

        is ReInit -> {
          proposal.validate()

          return ProcessProposalsResult.ReInitCommit(
            proposal.groupId,
            proposal.protocolVersion,
            proposal.cipherSuite,
            proposal.extensions,
            zeroesNh,
          )
        }
      }
    }

  return ProcessProposalsResult.CommitByMember(
    requiresUpdatePath,
    updatedTree,
    extensions,
    pskSecret,
    pskIds,
    welcomeTo,
  )
}

internal sealed interface ProcessProposalsResult {
  val updatePathRequired: Boolean

  val pskSecret: Secret
  val pskIds: List<PreSharedKeyId>
    get() = listOf()

  val updatedTree: RatchetTree?

  val welcomeTo: List<Pair<LeafIndex, KeyPackage>>?
    get() = null

  context(ActiveGroupState)
  fun createNextEpochState(
    commit: Commit,
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
  ): GroupState = nextEpoch(commit, groupContext, tree, keySchedule)

  data class CommitByMember(
    override val updatePathRequired: Boolean,
    override val updatedTree: RatchetTree,
    val extensions: List<GroupContextExtension<*>>?,
    override val pskSecret: Secret,
    override val pskIds: List<PreSharedKeyId>,
    override val welcomeTo: List<Pair<LeafIndex, KeyPackage>>,
  ) : ProcessProposalsResult

  data class ExternalJoin(
    val externalInitSecret: Secret,
    override val pskSecret: Secret,
    override val updatedTree: RatchetTree,
  ) : ProcessProposalsResult {
    override val updatePathRequired: Boolean = true
  }

  data class ReInitCommit(
    val groupId: ULID,
    val protocolVersion: ProtocolVersion,
    val cipherSuite: CipherSuite,
    val extensions: List<GroupContextExtension<*>>,
    override val pskSecret: Secret,
  ) : ProcessProposalsResult {
    override val updatePathRequired: Boolean = false
    override val updatedTree: RatchetTree? = null

    context(ActiveGroupState)
    override fun createNextEpochState(
      commit: Commit,
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
    ): GroupState = suspend(commit, groupContext, tree, keySchedule)
  }
}
