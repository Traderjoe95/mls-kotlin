package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.EpochError
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
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
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
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import de.traderjoe.ulid.ULID
import com.github.traderjoe95.mls.protocol.types.RatchetTree as RatchetTreeExt

sealed class GroupState(
  val groupContext: GroupContext,
  val tree: RatchetTree,
  val keySchedule: KeySchedule,
) : ICipherSuite by groupContext.cipherSuite {
  val protocolVersion: ProtocolVersion by lazy { groupContext.protocolVersion }
  val cipherSuite: CipherSuite by lazy { groupContext.cipherSuite }

  val groupId: ULID by lazy { groupContext.groupId }
  val epoch: ULong by lazy { groupContext.epoch }

  val extensions: GroupContextExtensions by lazy { groupContext.extensions }

  val confirmationTag: Mac by lazy { mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash) }

  val leafIndex: LeafIndex by lazy { tree.leafIndex }

  fun isActive(): Boolean = this is Active

  context(Raise<GroupSuspended>)
  inline fun <T> ensureActive(body: Active.() -> T): T =
    (this@GroupState as? Active)
      ?.body()
      ?: raise(GroupSuspended(groupId))

  data class CachedProposal(
    val ref: Proposal.Ref,
    val sender: LeafIndex?,
    val proposal: Proposal,
  ) {
    internal constructor(proposal: Proposal, sender: LeafIndex?, cipherSuite: ICipherSuite) : this(
      cipherSuite.makeProposalRef(proposal),
      sender,
      proposal,
    )
  }

  class Active internal constructor(
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
    val signingKey: SigningKey,
    private val storedProposals: Map<Int, CachedProposal> = mapOf(),
  ) : GroupState(groupContext, tree, keySchedule), SecretTree.Lookup {
    context(Raise<GroupSuspended>)
    fun storeProposal(
      proposal: Proposal,
      sender: LeafIndex?,
    ): GroupState =
      Active(
        groupContext,
        tree,
        keySchedule,
        signingKey,
        storedProposals + CachedProposal(proposal, sender, this).let { it.ref.hashCode to it },
      )

    fun getStoredProposals(): Map<Proposal.Ref, CachedProposal> = storedProposals.mapKeys { it.value.ref }

    context(Raise<InvalidCommit.UnknownProposal>)
    fun getProposal(proposalRef: Proposal.Ref): CachedProposal =
      storedProposals[proposalRef.hashCode]
        ?: raise(InvalidCommit.UnknownProposal(groupId, epoch, proposalRef))

    fun groupInfo(public: Boolean): GroupInfo =
      GroupInfo.create(
        leafIndex,
        signingKey,
        groupContext,
        listOfNotNull(
          RatchetTreeExt(tree),
          if (public) ExternalPub(deriveKeyPair(keySchedule.externalSecret).public) else null,
          *Extension.grease(),
        ),
        mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash),
      )

    context(Raise<RatchetError>, Raise<EpochError>)
    override suspend fun getNonceAndKey(
      epoch: ULong,
      leafIndex: LeafIndex,
      contentType: ContentType,
      generation: UInt,
    ): Pair<Nonce, Secret> = keySchedule.secretTree.getNonceAndKey(leafIndex, contentType, generation)

    context(Raise<SignatureError.VerificationKeyNotFound>, Raise<EpochError>)
    fun getVerificationKey(
      framedContent: FramedContent<*>,
    ): VerificationKey =
      if (framedContent.epoch > epoch) {
        raise(EpochError.FutureEpoch)
      } else if (framedContent.epoch < epoch) {
        raise(EpochError.PastEpoch)
      } else {
        when (framedContent.sender.type) {
          SenderType.Member ->
            tree.leafNodeOrNull(framedContent.sender.index!!)
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
      }

    fun nextEpoch(
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
    ): Active = Active(groupContext, tree, keySchedule, signingKey)

    fun suspend(
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
      reInit: ReInit,
    ): Suspended = Suspended(groupContext, tree, keySchedule, reInit)
  }

  class Suspended internal constructor(
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
    val reInit: ReInit,
  ) : GroupState(groupContext, tree, keySchedule), PskLookup {
    context(Raise<PskError>)
    override suspend fun getPreSharedKey(id: PreSharedKeyId): Secret =
      if (id is ResumptionPskId && id.pskGroupId == groupId && id.pskEpoch == epoch) {
        keySchedule.resumptionPsk
      } else {
        raise(PskError.PskNotFound(id))
      }
  }

  companion object
}
