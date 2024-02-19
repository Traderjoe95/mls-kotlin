package com.github.traderjoe95.mls.protocol.group

import arrow.core.Nel
import arrow.core.nonEmptyListOf
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.GroupInfoError
import com.github.traderjoe95.mls.protocol.error.GroupSuspended
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.RatchetError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.ExternalSenders
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.ExternalPskId
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.util.get
import de.traderjoe.ulid.ULID
import com.github.traderjoe95.mls.protocol.types.RatchetTree as RatchetTreeExt

sealed class GroupState : PskLookup, ICipherSuite, SecretTree.Lookup {
  abstract val settings: GroupSettings

  val protocolVersion: ProtocolVersion by lazy {
    settings.protocolVersion
  }

  val cipherSuite: CipherSuite by lazy {
    settings.cipherSuite
  }

  val groupId: ULID by lazy {
    settings.groupId
  }

  abstract val currentEpoch: ULong
  abstract val extensions: GroupContextExtensions

//  abstract val signingKey: SigningKey

  abstract val ownLeafIndex: LeafIndex

  abstract val tree: RatchetTree

  abstract val lastCommitProposals: List<Proposal>

  context(Raise<EpochError>)
  abstract fun tree(epoch: ULong): RatchetTree

  abstract val keySchedule: KeySchedule

  context(Raise<EpochError>)
  abstract fun keySchedule(epoch: ULong): KeySchedule

  abstract val groupContext: GroupContext

  context(Raise<EpochError>)
  abstract fun groupContext(epoch: ULong): GroupContext

  context(Raise<GroupInfoError>)
  abstract fun groupInfo(public: Boolean): GroupInfo

  context(Raise<SignatureError.VerificationKeyNotFound>, Raise<EpochError>)
  abstract fun getVerificationKey(framedContent: FramedContent<*>): VerificationKey

  //  context(Raise<InvalidCommit.UnknownProposal>)
//  abstract fun getProposal(proposalRef: Proposal.Ref): Pair<Proposal, LeafIndex?>
//
  context(Raise<GroupSuspended>)
  abstract fun storeProposal(
    proposal: Proposal,
    sender: LeafIndex?,
  ): Proposal.Ref

//  internal abstract fun privateKeyStore(): TreePrivateKeyStore

//  internal abstract fun nextEpoch(
//    commit: Commit,
//    groupContext: GroupContext,
//    tree: RatchetTree,
//    keySchedule: KeySchedule,
//    privateKeyStore: TreePrivateKeyStore,
//  ): GroupState

  fun isActive(): Boolean {
    return this is ActiveGroupState
  }

  context(Raise<GroupSuspended>)
  internal inline fun <T> ensureActive(body: ActiveGroupState.() -> T): T =
    (this@GroupState as? ActiveGroupState)
      ?.body()
      ?: raise(GroupSuspended(groupId))

  companion object
}

sealed class BaseGroupState(
  final override val settings: GroupSettings,
  internal val epochs: Nel<GroupEpoch>,
) : GroupState(), ICipherSuite by settings.cipherSuite {
  override val ownLeafIndex: LeafIndex
    get() = tree.leafIndex

  final override val currentEpoch: ULong by lazy {
    epochs.head.epoch
  }

  final override val extensions: GroupContextExtensions by lazy {
    epochs.head.extensions
  }

  final override val tree: RatchetTree by lazy {
    epochs.head.tree
  }

  context(Raise<EpochError>)
  final override fun tree(epoch: ULong): RatchetTree = findEpoch(epoch).tree

  final override val keySchedule: KeySchedule by lazy {
    epochs.head.keySchedule
  }

  context(Raise<EpochError>)
  final override fun keySchedule(epoch: ULong): KeySchedule = findEpoch(epoch).keySchedule

  final override val groupContext: GroupContext by lazy {
    GroupContext.create(settings, epochs.head)
  }

  context(Raise<EpochError>)
  final override fun groupContext(epoch: ULong): GroupContext = GroupContext.create(settings, findEpoch(epoch))

  context(Raise<GroupInfoError>)
  final override fun groupInfo(public: Boolean): GroupInfo =
    ensureActive {
      GroupInfo.create(
        ownLeafIndex,
        signingKey,
        groupContext,
        listOfNotNull(
          RatchetTreeExt(tree),
          if (public) ExternalPub(deriveKeyPair(keySchedule.externalSecret).public) else null,
          *Extension.grease(),
        ),
        epochs.head.confirmationTag,
      )
    }

  context(Raise<SignatureError.VerificationKeyNotFound>, Raise<EpochError>)
  final override fun getVerificationKey(framedContent: FramedContent<*>): VerificationKey =
    when (framedContent.sender.type) {
      SenderType.Member ->
        tree(framedContent.epoch).leafNodeOrNull(framedContent.sender.index!!)
          ?.verificationKey

      SenderType.External ->
        groupContext.extension<ExternalSenders>()
          ?.externalSenders
          ?.getOrNull(framedContent.sender.index!!.value.toInt())
          ?.verificationKey

      SenderType.NewMemberCommit ->
        (framedContent.content as? Commit)
          ?.updatePath?.getOrNull()
          ?.leafNode
          ?.verificationKey

      SenderType.NewMemberProposal ->
        (framedContent.content as? Add)
          ?.keyPackage
          ?.leafNode
          ?.verificationKey

      else -> error("Unreachable")
    } ?: raise(SignatureError.VerificationKeyNotFound(framedContent.sender))

  context(Raise<EpochError>)
  private fun findEpoch(epoch: ULong): GroupEpoch =
    when {
      epoch > epochs.head.epoch -> raise(EpochError.FutureEpoch)
      epoch < epochs.head.epoch + 1U - epochs.size.toUInt() -> raise(EpochError.OutdatedEpoch)
      else -> epochs[epochs.head.epoch - epoch]
    }

  final override val lastCommitProposals: List<Proposal>
    get() =
      epochs.head.initiatingCommit.proposals.map {
        when (it) {
          is Proposal -> it
          is Proposal.Ref -> epochs[1].proposals[it.hashCode]!!.first
        }
      }

  context(ApplicationCtx<Identity>, Raise<PskError>)
  final override suspend fun <Identity : Any> getPreSharedKey(id: PreSharedKeyId): Secret =
    when (id) {
      is ExternalPskId -> getExternalPsk(id.pskId)
      is ResumptionPskId ->
        when {
          id.pskGroupId != settings.groupId -> getResumptionPsk(id.pskGroupId, id.pskEpoch)
          id.pskEpoch == currentEpoch -> keySchedule.resumptionPsk
          else -> keySchedule(id.pskEpoch).resumptionPsk
        }
    }

  context(Raise<RatchetError>, Raise<EpochError>)
  final override suspend fun getNonceAndKey(
    epoch: ULong,
    leafIndex: LeafIndex,
    contentType: ContentType,
    generation: UInt,
  ): Pair<Nonce, Secret> = keySchedule(epoch).secretTree.getNonceAndKey(leafIndex, contentType, generation)

  context(Raise<GroupSuspended>)
  final override fun storeProposal(
    proposal: Proposal,
    sender: LeafIndex?,
  ): Proposal.Ref =
    ensureActive {
      makeProposalRef(proposal).also { ref ->
        epochs.head.proposals[ref.hashCode] = proposal to sender
      }
    }
}

internal class ActiveGroupState internal constructor(
  settings: GroupSettings,
  epochs: Nel<GroupEpoch>,
  val signingKey: SigningKey,
) : BaseGroupState(settings, epochs) {
  context(Raise<InvalidCommit.UnknownProposal>)
  fun getProposal(proposalRef: Proposal.Ref): Pair<Proposal, LeafIndex?> =
    epochs.head.proposals[proposalRef.hashCode]
      ?: raise(
        InvalidCommit.UnknownProposal(
          settings.groupId,
          currentEpoch,
          proposalRef,
        ),
      )

  fun nextEpoch(
    commit: Commit,
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
  ): ActiveGroupState =
    ActiveGroupState(
      settings,
      nonEmptyListOf(
        GroupEpoch.from(
          groupContext,
          tree,
          keySchedule,
          commit,
        ),
        *epochs.take(settings.keepPastEpochs.toInt() - 1).toTypedArray(),
      ),
      signingKey,
    )

  fun suspend(
    commit: Commit,
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
  ): SuspendedGroupState =
    SuspendedGroupState(
      settings,
      nonEmptyListOf(
        GroupEpoch.from(
          groupContext,
          tree,
          keySchedule,
          commit,
        ),
        *epochs.take(settings.keepPastEpochs.toInt() - 1).toTypedArray(),
      ),
    )
}

internal class SuspendedGroupState internal constructor(
  settings: GroupSettings,
  epochs: Nel<GroupEpoch>,
) : BaseGroupState(settings, epochs)
