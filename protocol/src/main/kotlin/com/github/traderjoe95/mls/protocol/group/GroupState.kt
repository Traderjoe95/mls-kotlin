package com.github.traderjoe95.mls.protocol.group

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.CreateUpdateError
import com.github.traderjoe95.mls.protocol.error.GroupActive
import com.github.traderjoe95.mls.protocol.error.GroupInfoError
import com.github.traderjoe95.mls.protocol.error.GroupSuspended
import com.github.traderjoe95.mls.protocol.error.InvalidCommit
import com.github.traderjoe95.mls.protocol.error.MessageRecipientError
import com.github.traderjoe95.mls.protocol.error.ProcessMessageError
import com.github.traderjoe95.mls.protocol.error.ProposalValidationError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.message.AuthHandshakeContent
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.GroupMessageFactory
import com.github.traderjoe95.mls.protocol.message.HandshakeMessage
import com.github.traderjoe95.mls.protocol.message.MlsHandshakeMessage
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.LeafNodeExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType.Member
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.UpdateLeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.util.hex
import java.time.Instant
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

  val members: List<LeafNode<*>> by lazy { tree.leaves.filterNotNull() }

  fun isActive(): Boolean = this is Active

  context(Raise<GroupSuspended>)
  inline fun <T> ensureActive(body: Active.() -> T): T = ensureActive().body()

  context(Raise<GroupSuspended>)
  fun ensureActive(): Active = (this as? Active) ?: raise(GroupSuspended(groupId))

  context(Raise<GroupActive>)
  inline fun <T> ensureSuspended(body: Suspended.() -> T): T = ensureSuspended().body()

  context(Raise<GroupActive>)
  fun ensureSuspended(): Suspended = (this as? Suspended) ?: raise(GroupActive(groupId))

  fun coerceActive(): Active = this as Active

  fun coerceSuspended(): Suspended = this as Suspended

  class Active internal constructor(
    groupContext: GroupContext,
    tree: RatchetTree,
    keySchedule: KeySchedule,
    val signaturePrivateKey: SignaturePrivateKey,
    private val cachedProposals: Map<String, CachedProposal> = mapOf(),
  ) : GroupState(groupContext, tree, keySchedule), SecretTree.Lookup, PskLookup {
    @get:JvmName("secretTree")
    val secretTree: SecretTree by lazy {
      SecretTree.create(
        cipherSuite,
        keySchedule.encryptionSecret,
        tree.leaves.uSize,
      )
    }

    @get:JvmName("messages")
    val messages: GroupMessageFactory by lazy { GroupMessageFactory(this) }

    @get:JvmName("validations")
    val validations: Validations by lazy { Validations(this) }

    internal var cachedUpdate: CachedUpdate? = null

    context(Raise<ProposalValidationError>)
    private suspend fun storeProposal(proposal: AuthenticatedContent<Proposal>): Active =
      Active(
        groupContext,
        tree,
        keySchedule,
        signaturePrivateKey,
        cachedProposals +
          CachedProposal(
            validations.validated(proposal).bind(),
            cipherSuite,
          ).let { it.ref.hex to it },
      )

    fun getStoredProposals(): List<CachedProposal> = cachedProposals.values.toList()

    context(Raise<InvalidCommit.UnknownProposal>)
    fun getStoredProposal(proposalRef: Proposal.Ref): CachedProposal =
      cachedProposals[proposalRef.hex]
        ?: raise(InvalidCommit.UnknownProposal(groupId, epoch, proposalRef))

    fun groupInfo(
      inlineTree: Boolean = true,
      public: Boolean = false,
    ): Either<GroupInfoError, GroupInfo> =
      GroupInfo.create(
        groupContext,
        mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash),
        listOfNotNull(
          if (inlineTree) RatchetTreeExt(tree) else null,
          if (public) ExternalPub(deriveKeyPair(keySchedule.externalSecret).public) else null,
          *Extension.grease(),
        ),
        leafIndex,
        signaturePrivateKey,
      )

    context(Raise<PskError>)
    override suspend fun resolvePsk(id: PreSharedKeyId): Secret =
      if (id is ResumptionPskId && id.pskGroupId == groupId && id.pskEpoch == epoch) {
        keySchedule.resumptionPsk
      } else {
        raise(PskError.PskNotFound(id))
      }

    suspend fun <Identity : Any> process(
      mlsMessage: MlsHandshakeMessage,
      authenticationService: AuthenticationService<Identity>,
      psks: PskLookup = PskLookup.EMPTY,
      cachedState: GroupState? = null,
    ): Either<ProcessMessageError, GroupState> = process(mlsMessage.message, authenticationService, psks, cachedState)

    suspend fun <Identity : Any> process(
      message: HandshakeMessage,
      authenticationService: AuthenticationService<Identity>,
      psks: PskLookup = PskLookup.EMPTY,
      cachedState: GroupState? = null,
    ): Either<ProcessMessageError, GroupState> =
      either {
        process(message.unprotect(this@Active).bind(), authenticationService, psks, cachedState)
      }

    context(Raise<ProcessMessageError>)
    @Suppress("UNCHECKED_CAST")
    internal suspend fun <Identity : Any> process(
      message: AuthHandshakeContent,
      authenticationService: AuthenticationService<Identity>,
      psks: PskLookup = PskLookup.EMPTY,
      cachedState: GroupState? = null,
    ): GroupState {
      ensure(message.groupId eq groupId) { MessageRecipientError.WrongGroup(message.groupId, groupId) }
      ensure(message.epoch == epoch) {
        ProcessMessageError.HandshakeMessageForWrongEpoch(groupId, message.epoch, epoch)
      }

      return when (message.content.content) {
        is Proposal ->
          storeProposal(message as AuthenticatedContent<Proposal>)

        is Commit ->
          if (message.sender.type == Member && message.sender.index == leafIndex) {
            cachedState ?: raise(ProcessMessageError.MustUseCachedStateForOwnCommit)
          } else {
            processCommit(message as AuthenticatedContent<Commit>, authenticationService, psks).bind()
          }
      }
    }

    context(Raise<CreateUpdateError>)
    fun updateLeafNode(
      newEncryptionKeyPair: HpkeKeyPair,
      newSignatureKeyPair: SignatureKeyPair? = null,
      newCredential: Credential? = null,
      newCapabilities: Capabilities? = null,
      newExtensions: LeafNodeExtensions? = null,
    ): UpdateLeafNode {
      if (cachedUpdate != null) raise(CreateUpdateError.AlreadyUpdatedThisEpoch)

      val oldLeaf = tree.leafNode(leafIndex)
      val newLeaf =
        LeafNode.update(
          cipherSuite,
          newSignatureKeyPair ?: SignatureKeyPair(signaturePrivateKey, oldLeaf.signaturePublicKey),
          newEncryptionKeyPair.public,
          newCredential ?: oldLeaf.credential,
          newCapabilities ?: oldLeaf.capabilities,
          newExtensions ?: oldLeaf.extensions,
          leafIndex,
          groupId,
        ).bind()

      cachedUpdate = CachedUpdate(newLeaf, newEncryptionKeyPair.private, newSignatureKeyPair?.private)

      return newLeaf
    }

    fun nextEpoch(
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
      newSignaturePrivateKey: SignaturePrivateKey = signaturePrivateKey,
    ): Active = Active(groupContext, tree, keySchedule, newSignaturePrivateKey)

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
    override suspend fun resolvePsk(id: PreSharedKeyId): Secret =
      if (id is ResumptionPskId && id.pskGroupId == groupId && id.pskEpoch == epoch) {
        keySchedule.resumptionPsk
      } else {
        raise(PskError.PskNotFound(id))
      }
  }

  internal data class CachedUpdate(
    val leafNode: UpdateLeafNode,
    val encryptionPrivateKey: HpkePrivateKey,
    val signaturePrivateKey: SignaturePrivateKey?,
  )

  data class CachedProposal(
    val ref: Proposal.Ref,
    val sender: LeafIndex?,
    val proposal: Proposal,
    val received: Instant = Instant.now(),
  ) {
    internal constructor(
      proposal: AuthenticatedContent<Proposal>,
      cipherSuite: ICipherSuite,
    ) : this(
      cipherSuite.makeProposalRef(proposal),
      proposal.sender.takeIf { it.type == Member }?.index,
      proposal.content.content,
    )
  }

  companion object
}
