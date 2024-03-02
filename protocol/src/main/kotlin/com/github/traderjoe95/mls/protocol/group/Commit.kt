package com.github.traderjoe95.mls.protocol.group

import arrow.core.Either
import arrow.core.None
import arrow.core.Option
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.nullable
import arrow.core.toOption
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.CommitError
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.RecipientCommitError
import com.github.traderjoe95.mls.protocol.error.RecipientTreeUpdateError
import com.github.traderjoe95.mls.protocol.error.RemoveValidationError
import com.github.traderjoe95.mls.protocol.error.RemovedFromGroup
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.GroupInfo.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.GroupSecrets
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MessageOptions
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.UsePublicMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.psk.ResolvedPsk.Companion.updatePskSecret
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.applyUpdatePath
import com.github.traderjoe95.mls.protocol.tree.applyUpdatePathExternalJoin
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.findEquivalentLeaf
import com.github.traderjoe95.mls.protocol.tree.validate
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ProposalOrRef
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import com.github.traderjoe95.mls.protocol.types.RatchetTree as RatchetTreeExt

suspend fun <Identity : Any> GroupState.Active.prepareCommit(
  proposals: List<ProposalOrRef>,
  authenticationService: AuthenticationService<Identity>,
  messageOptions: MessageOptions = UsePublicMessage,
  authenticatedData: ByteArray = byteArrayOf(),
  inReInit: Boolean = false,
  inBranch: Boolean = false,
  psks: PskLookup = this,
): Either<SenderCommitError, PrepareCommitResult> =
  either {
    val proposalResult = processProposals(proposals, None, authenticationService, leafIndex, inReInit, inBranch, psks)

    val (updatedTree, updatePath, pathSecrets) =
      if (proposalResult.updatePathRequired) {
        createUpdatePath(
          (proposalResult.updatedTree ?: tree),
          proposalResult.newMemberLeafIndices(),
          groupContext.withExtensions((proposalResult as? ProcessProposalsResult.CommitByMember)?.extensions),
          signaturePrivateKey,
        )
      } else {
        Triple((proposalResult.updatedTree ?: tree), null, listOf())
      }

    val commitSecret = nullable { deriveSecret(pathSecrets.lastOrNull().bind(), "path") } ?: zeroesNh

    val partialCommit =
      messages.createAuthenticatedContent(
        Commit(proposals, updatePath.toOption()),
        messageOptions,
        authenticatedData,
      )

    val updatedGroupContext =
      groupContext.evolve(
        partialCommit.wireFormat,
        partialCommit.content,
        partialCommit.signature,
        updatedTree,
        newExtensions = (proposalResult as? ProcessProposalsResult.CommitByMember)?.extensions,
      )

    val (newKeySchedule, joinerSecret, welcomeSecret) =
      keySchedule.nextEpoch(
        commitSecret,
        updatedGroupContext,
        proposalResult.pskSecret,
        (proposalResult as? ProcessProposalsResult.ExternalJoin)?.externalInitSecret,
      )

    val confirmationTag = mac(newKeySchedule.confirmationKey, updatedGroupContext.confirmedTranscriptHash)

    val updatedGroupState =
      proposalResult.createNextEpochState(
        updatedGroupContext.withInterimTranscriptHash(
          newInterimTranscriptHash(
            cipherSuite,
            updatedGroupContext.confirmedTranscriptHash,
            confirmationTag,
          ),
        ),
        updatedTree,
        newKeySchedule,
      )
    val groupInfo =
      GroupInfo.create(
        updatedGroupContext,
        confirmationTag,
        listOfNotNull(
          RatchetTreeExt(updatedTree),
          *Extension.grease(),
        ),
        leafIndex,
        signaturePrivateKey,
      ).bind()

    PrepareCommitResult(
      updatedGroupState,
      messages.protectCommit(partialCommit, confirmationTag, messageOptions),
      proposalResult.welcomeTo
        ?.takeIf { it.isNotEmpty() }
        ?.let { newMembers ->
          listOf(
            PrepareCommitResult.WelcomeMessage(
              newMembers.createWelcome(
                groupInfo,
                updatedTree,
                pathSecrets,
                welcomeSecret,
                joinerSecret,
                proposalResult.pskIds,
              ),
              newMembers.map { it.second },
            ),
          )
        } ?: listOf(),
    )
  }

suspend fun <Identity : Any> GroupState.Active.processCommit(
  authenticatedCommit: AuthenticatedContent<Commit>,
  authenticationService: AuthenticationService<Identity>,
  psks: PskLookup = this,
): Either<RecipientCommitError, GroupState> =
  either {
    val commit = authenticatedCommit.content
    val proposalResult = commit.content.validateAndApply(commit.sender, psks, authenticationService)
    val updatePath = commit.content.updatePath

    val preTree = proposalResult.updatedTree ?: tree

    with(preTree) {
      if (leafIndex.isBlank) raise(RemovedFromGroup)
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
      keySchedule.nextEpoch(
        commitSecret,
        updatedGroupContext,
        proposalResult.pskSecret,
        (proposalResult as? ProcessProposalsResult.ExternalJoin)?.externalInitSecret,
      )

    verifyMac(
      newKeySchedule.confirmationKey,
      updatedGroupContext.confirmedTranscriptHash,
      authenticatedCommit.confirmationTag!!,
    )

    proposalResult.createNextEpochState(
      updatedGroupContext.withInterimTranscriptHash(
        newInterimTranscriptHash(
          cipherSuite,
          updatedGroupContext.confirmedTranscriptHash,
          authenticatedCommit.confirmationTag,
        ),
      ),
      updatedTree,
      newKeySchedule,
    )
  }

context(GroupState.Active, Raise<CommitError>)
private suspend fun <Identity : Any> Commit.validateAndApply(
  sender: Sender,
  psks: PskLookup,
  authenticationService: AuthenticationService<Identity>,
): ProcessProposalsResult =
  processProposals(
    proposals,
    updatePath,
    authenticationService,
    when (sender.type) {
      SenderType.Member -> sender.index!!
      SenderType.NewMemberCommit -> null
      else -> raise(InvalidCommit.BadCommitSender(sender.type))
    },
    inReInit = false,
    inBranch = false,
    psks,
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

context(Raise<RecipientTreeUpdateError>)
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

context(GroupState.Active, Raise<SenderCommitError>)
private fun List<Pair<LeafIndex, KeyPackage>>.createWelcome(
  groupInfo: GroupInfo,
  newTree: RatchetTree,
  pathSecrets: List<Secret>,
  welcomeSecret: Secret,
  joinerSecret: Secret,
  pskIds: List<PreSharedKeyId>,
): MlsMessage<Welcome> {
  val welcomeNonce = expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), nonceLen).asNonce
  val welcomeKey = expandWithLabel(welcomeSecret, "key", byteArrayOf(), keyLen)

  val encryptedGroupInfo = encryptAead(welcomeKey, welcomeNonce, Aad.empty, groupInfo.encodeUnsafe())

  val filteredPath = newTree.filteredDirectPath(leafIndex).map { it.first }

  val encryptedGroupSecrets =
    map { (newLeaf, keyPackage) ->
      val commonAncestorIdx = filteredPath.indexOfFirst { newLeaf.isInSubtreeOf(it) }
      val pathSecret = pathSecrets.getOrNull(commonAncestorIdx).toOption()

      GroupSecrets(joinerSecret, pathSecret, pskIds)
        .encrypt(cipherSuite, keyPackage, encryptedGroupInfo)
    }.bindAll()

  return MlsMessage.welcome(
    groupContext.cipherSuite,
    encryptedGroupSecrets,
    encryptedGroupInfo,
  )
}

context(Raise<CommitError>)
private suspend fun <Identity : Any> GroupState.Active.processProposals(
  proposals: List<ProposalOrRef>,
  updatePath: Option<UpdatePath>,
  authenticationService: AuthenticationService<Identity>,
  committerLeafIdx: LeafIndex?,
  inReInit: Boolean = false,
  inBranch: Boolean = false,
  psks: PskLookup,
): ProcessProposalsResult {
  val resolved: ResolvedProposals = mutableMapOf()

  proposals.forEach { proposalOrRef ->
    val (proposal, sender) =
      when (proposalOrRef) {
        is Proposal -> proposalOrRef to committerLeafIdx

        is Proposal.Ref ->
          if (committerLeafIdx == null) {
            raise(InvalidCommit.NoProposalRefAllowed)
          } else {
            getStoredProposal(proposalOrRef).let { it.proposal to it.sender }
          }
      }

    resolved.compute(proposal.type) { _, current -> (current ?: listOf()) + (proposal to sender) }
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

  var newSignaturePrivateKey: SignaturePrivateKey? = null

  ProposalType.ORDER.asSequence()
    .flatMap { resolved.getAll<Proposal>(it).asSequence() }
    .forEach { (proposal, from) ->
      when (proposal) {
        is GroupContextExtensions -> {
          validations.validated(
            proposal,
            updatedTree,
            resolved.getAll<Remove>(ProposalType.Remove).map { it.first.removed }.toSet(),
          )

          extensions = proposal.extensions
        }

        is Update -> {
          validations.validated(proposal, from!!, updatedTree).bind()

          val cached = cachedUpdate

          updatedTree =
            when {
              from != leafIndex -> updatedTree.update(from, proposal.leafNode)

              cached != null && proposal.leafNode == cached.leafNode -> {
                newSignaturePrivateKey = cached.signaturePrivateKey
                updatedTree.update(from, proposal.leafNode, cached.encryptionPrivateKey)
              }

              cached != null ->
                raise(CommitError.CachedUpdateDoesNotMatch(cached.leafNode, proposal.leafNode))

              else -> raise(CommitError.CachedUpdateMissing)
            }

          requiresUpdatePath = true
        }

        is Remove -> {
          validations.validated(proposal, updatedTree).bind()

          if (committerLeafIdx == null) {
            val expectedClient = updatePath.getOrNull()!!.leafNode.credential

            if (!authenticationService.isSameClient(expectedClient, updatedTree.leafNode(proposal.removed).credential).bind()) {
              raise(RemoveValidationError.UnauthorizedExternalRemove(proposal.removed))
            }
          }

          updatedTree = updatedTree.remove(proposal.removed)
          requiresUpdatePath = true
        }

        is Add -> {
          validations.validated(proposal, updatedTree).bind()

          with(authenticationService) { updatedTree.findEquivalentLeaf(proposal.keyPackage.leafNode) }
            ?.also { raise(InvalidCommit.AlreadyMember(proposal.keyPackage, it)) }

          val (treeWithNewMember, newMemberLeaf) = updatedTree.insert(proposal.keyPackage.leafNode)

          updatedTree = treeWithNewMember
          welcomeTo.add(newMemberLeaf to proposal.keyPackage)
        }

        is PreSharedKey -> {
          val psk = validations.validated(proposal, psks, inReInit, inBranch).bind()!!

          pskSecret = updatePskSecret(pskSecret, proposal.pskId, psk, pskIndex++, pskCount)
          pskIds.add(proposal.pskId)
        }

        is ExternalInit ->
          return ProcessProposalsResult.ExternalJoin(
            externalInitSecret = export(proposal.kemOutput, deriveKeyPair(keySchedule.externalSecret), "").bind(),
            pskSecret,
            updatedTree,
          )

        is ReInit -> {
          validations.validated(proposal).bind()

          return ProcessProposalsResult.ReInitCommit(proposal, zeroesNh)
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
    newSignaturePrivateKey,
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

  context(GroupState.Active)
  fun createNextEpochState(
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
  ): GroupState = nextEpoch(groupContext, tree, keySchedule)

  data class CommitByMember(
    override val updatePathRequired: Boolean,
    override val updatedTree: RatchetTree,
    val extensions: List<GroupContextExtension<*>>?,
    override val pskSecret: Secret,
    override val pskIds: List<PreSharedKeyId>,
    override val welcomeTo: List<Pair<LeafIndex, KeyPackage>>,
    val newSignaturePrivateKey: SignaturePrivateKey?,
  ) : ProcessProposalsResult {
    context(GroupState.Active)
    override fun createNextEpochState(
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
    ): GroupState = nextEpoch(groupContext, tree, keySchedule, newSignaturePrivateKey ?: signaturePrivateKey)
  }

  data class ExternalJoin(
    val externalInitSecret: Secret,
    override val pskSecret: Secret,
    override val updatedTree: RatchetTree,
  ) : ProcessProposalsResult {
    override val updatePathRequired: Boolean = true
  }

  data class ReInitCommit(
    val reInit: ReInit,
    override val pskSecret: Secret,
  ) : ProcessProposalsResult {
    override val updatePathRequired: Boolean = false
    override val updatedTree: RatchetTree? = null

    context(GroupState.Active)
    override fun createNextEpochState(
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
    ): GroupState = suspend(groupContext, tree, keySchedule, reInit)
  }
}
