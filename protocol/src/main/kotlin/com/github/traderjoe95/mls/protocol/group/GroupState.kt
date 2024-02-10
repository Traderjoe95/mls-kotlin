package com.github.traderjoe95.mls.protocol.group

import arrow.core.Nel
import arrow.core.nonEmptyListOf
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.RatchetError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.SecretTree
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
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.util.get
import de.traderjoe.ulid.ULID

interface GroupState : SecretTree, PskLookup, ICipherSuite {
  val settings: GroupSettings

  val groupId: ULID
    get() = settings.groupId

  val currentEpoch: ULong

  val cipherSuite: CipherSuite
  val extensions: GroupContextExtensions

  val signingKey: SigningKey
  val ownLeafNodeIndex: UInt

  val ownLeafIndex: UInt
    get() = ownLeafNodeIndex / 2U

  val tree: RatchetTree

  val lastCommitProposals: List<Proposal>

  context(Raise<EpochError>)
  fun tree(epoch: ULong): RatchetTree

  val keySchedule: KeySchedule

  context(Raise<EpochError>)
  fun keySchedule(epoch: ULong): KeySchedule

  val groupContext: GroupContext

  context(Raise<EpochError>)
  fun groupContext(epoch: ULong): GroupContext

  context(Raise<SignatureError.VerificationKeyNotFound>, Raise<EpochError>)
  fun getVerificationKey(
    framedContent: FramedContent<*>,
  ): VerificationKey

  context(Raise<InvalidCommit.UnknownProposal>)
  fun getProposal(proposalRef: Proposal.Ref): Pair<Proposal, UInt?>

  context(Raise<EncoderError>)
  fun storeProposal(
    proposal: Proposal,
    sender: UInt?,
  ): Proposal.Ref

  fun nextEpoch(
    commit: Commit,
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
  ): GroupState

  companion object
}

internal class GroupStateImpl(
  override val settings: GroupSettings,
  private val epochs: Nel<GroupEpoch>,
  override val signingKey: SigningKey,
  override val ownLeafNodeIndex: UInt,
) : GroupState,
  ICipherSuite by settings.cipherSuite {
  override val currentEpoch: ULong by lazy {
    epochs.head.epoch
  }

  override val cipherSuite: CipherSuite by lazy {
    settings.cipherSuite
  }

  override val extensions: GroupContextExtensions by lazy {
    epochs.head.extensions
  }

  override val tree: RatchetTree by lazy {
    epochs.head.tree
  }

  context(Raise<EpochError>)
  override fun tree(epoch: ULong): RatchetTree = findEpoch(epoch).tree

  override val keySchedule: KeySchedule by lazy {
    epochs.head.keySchedule
  }

  override val lastCommitProposals: List<Proposal>
    get() =
      epochs.head.initiatingCommit.proposals.map {
        when (it) {
          is Proposal -> it
          is Proposal.Ref -> epochs[1].proposals[it.hashCode]!!.first
        }
      }

  context(Raise<EpochError>)
  override fun keySchedule(epoch: ULong): KeySchedule = findEpoch(epoch).keySchedule

  override val groupContext: GroupContext by lazy {
    GroupContext.create(settings, epochs.head)
  }

  context(Raise<EpochError>)
  override fun groupContext(epoch: ULong): GroupContext = GroupContext.create(settings, findEpoch(epoch))

  context(Raise<EpochError>)
  private fun findEpoch(epoch: ULong): GroupEpoch =
    when {
      epoch > epochs.head.epoch -> raise(EpochError.FutureEpoch)
      epoch < epochs.head.epoch + 1U - epochs.size.toUInt() -> raise(EpochError.OutdatedEpoch)
      else -> epochs[epochs.head.epoch - epoch]
    }

  context(Raise<SignatureError.VerificationKeyNotFound>, Raise<EpochError>)
  override fun getVerificationKey(framedContent: FramedContent<*>): VerificationKey =
    when (framedContent.sender.type) {
      SenderType.Member ->
        tree(framedContent.epoch).leaves.getOrNull(framedContent.sender.index!!.toInt())
          ?.node
          ?.verificationKey

      SenderType.External ->
        groupContext.extension<ExternalSenders>()
          ?.externalSenders
          ?.getOrNull(framedContent.sender.index!!.toInt())
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

  context(ApplicationCtx<Identity>, Raise<PskError>)
  override suspend fun <Identity : Any> getPreSharedKey(id: PreSharedKeyId): Secret =
    when (id) {
      is ExternalPskId -> getExternalPsk(id.pskId)
      is ResumptionPskId ->
        when {
          id.pskGroupId != settings.groupId -> getResumptionPsk(id.pskGroupId, id.pskEpoch)
          id.pskEpoch == currentEpoch -> keySchedule.resumptionPsk
          else -> keySchedule(id.pskEpoch).resumptionPsk
        }
    }

  context(Raise<InvalidCommit.UnknownProposal>)
  override fun getProposal(proposalRef: Proposal.Ref): Pair<Proposal, UInt?> =
    epochs.head.proposals[proposalRef.hashCode]
      ?: raise(
        InvalidCommit.UnknownProposal(
          settings.groupId,
          currentEpoch,
          proposalRef,
        ),
      )

  context(Raise<EncoderError>)
  override fun storeProposal(
    proposal: Proposal,
    sender: UInt?,
  ): Proposal.Ref =
    makeProposalRef(proposal).also { ref ->
      epochs.head.proposals[ref.hashCode] = proposal to sender
    }

  override fun nextEpoch(
    commit: Commit,
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
  ): GroupState =
    GroupStateImpl(
      settings,
      nonEmptyListOf(
        GroupEpoch(
          groupContext.epoch,
          tree,
          keySchedule,
          groupContext.confirmedTranscriptHash,
          groupContext.extensions,
          groupContext.interimTranscriptHash,
          commit,
        ),
        *epochs.take(settings.keepPastEpochs.toInt() - 1).toTypedArray(),
      ),
      signingKey,
      ownLeafNodeIndex,
    )

  context(Raise<RatchetError>)
  override suspend fun getNonceAndKey(
    epoch: ULong,
    leafIndex: UInt,
    contentType: ContentType,
    generation: UInt,
  ): Pair<Nonce, Secret> = keySchedule(epoch).getNonceAndKey(leafIndex, contentType, generation)

  override suspend fun getNonceAndKey(
    leafIndex: UInt,
    contentType: ContentType,
  ): Triple<Nonce, Secret, UInt> = keySchedule.getNonceAndKey(leafIndex, contentType)
}
