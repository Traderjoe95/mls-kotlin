package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.GroupSuspended
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.ProcessMessageError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.message.AuthHandshakeContent
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.HandshakeMessage
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType.Member
import com.github.traderjoe95.mls.protocol.types.RatchetTree as RatchetTreeExt

sealed class GroupState(
  val groupContext: GroupContext,
  val tree: RatchetTree,
  val keySchedule: KeySchedule,
) : ICipherSuite by groupContext.cipherSuite {
  val protocolVersion: ProtocolVersion by lazy { groupContext.protocolVersion }
  val cipherSuite: CipherSuite by lazy { groupContext.cipherSuite }

  val groupId: GroupId by lazy { groupContext.groupId }
  val epoch: ULong by lazy { groupContext.epoch }

  val extensions: GroupContextExtensions by lazy { groupContext.extensions }

  val confirmationTag: Mac by lazy { mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash) }

  val leafIndex: LeafIndex by lazy { tree.leafIndex }

  val secretTree: SecretTree by lazy { SecretTree.create(cipherSuite, keySchedule.encryptionSecret, tree.leaves.uSize) }

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
    val signaturePrivateKey: SignaturePrivateKey,
    private val storedProposals: Map<Int, CachedProposal> = mapOf(),
  ) : GroupState(groupContext, tree, keySchedule), SecretTree.Lookup, PskLookup {
    fun storeProposal(
      proposal: Proposal,
      sender: LeafIndex?,
    ): Active =
      Active(
        groupContext,
        tree,
        keySchedule,
        signaturePrivateKey,
        storedProposals + CachedProposal(proposal, sender, this).let { it.ref.hashCode to it },
      )

    fun getStoredProposals(): Map<Proposal.Ref, CachedProposal> = storedProposals.mapKeys { it.value.ref }

    context(Raise<InvalidCommit.UnknownProposal>)
    fun getProposal(proposalRef: Proposal.Ref): CachedProposal =
      storedProposals[proposalRef.hashCode]
        ?: raise(InvalidCommit.UnknownProposal(groupId, epoch, proposalRef))

    fun groupInfo(
      inlineTree: Boolean = true,
      public: Boolean = false,
    ): GroupInfo =
      GroupInfo.create(
        leafIndex,
        signaturePrivateKey,
        groupContext,
        mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash),
        listOfNotNull(
          if (inlineTree) RatchetTreeExt(tree) else null,
          if (public) ExternalPub(deriveKeyPair(keySchedule.externalSecret).public) else null,
          *Extension.grease(),
        ),
      )

    context(Raise<PskError>)
    override suspend fun getPreSharedKey(id: PreSharedKeyId): Secret =
      if (id is ResumptionPskId && id.pskGroupId == groupId && id.pskEpoch == epoch) {
        keySchedule.resumptionPsk
      } else {
        raise(PskError.PskNotFound(id))
      }

    context(Raise<ProcessMessageError>, AuthenticationService<Identity>)
    suspend fun <Identity : Any, Err : ProcessMessageError> process(
      message: HandshakeMessage<Err>,
      psks: PskLookup = PskLookup.EMPTY,
      cachedState: GroupState? = null,
    ): GroupState = process(message.unprotect(this), psks, cachedState)

    context(Raise<ProcessMessageError>, AuthenticationService<Identity>)
    @Suppress("UNCHECKED_CAST")
    internal suspend fun <Identity : Any> process(
      message: AuthHandshakeContent,
      psks: PskLookup = PskLookup.EMPTY,
      cachedState: GroupState? = null,
    ): GroupState =
      when (val c = message.content.content) {
        is Proposal ->
          storeProposal(c, message.content.sender.takeIf { it.type == Member }?.index)

        is Commit ->
          if (message.sender.type == Member && message.sender.index == leafIndex) {
            cachedState ?: raise(ProcessMessageError.MustUseCachedStateForOwnCommit)
          } else {
            processCommit(message as AuthenticatedContent<Commit>, psks)
          }
      }

    fun nextEpoch(
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
    ): Active = Active(groupContext, tree, keySchedule, signaturePrivateKey)

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
