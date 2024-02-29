package com.github.traderjoe95.mls.protocol.client

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.recover
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.CreateAddError
import com.github.traderjoe95.mls.protocol.error.CreatePreSharedKeyError
import com.github.traderjoe95.mls.protocol.error.CreateRemoveError
import com.github.traderjoe95.mls.protocol.error.CreateUpdateError
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.EpochError.EpochNotAvailable
import com.github.traderjoe95.mls.protocol.error.EpochError.FutureEpoch
import com.github.traderjoe95.mls.protocol.error.ExternalJoinError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.GroupInfoError
import com.github.traderjoe95.mls.protocol.error.HistoryAccessError
import com.github.traderjoe95.mls.protocol.error.MessageRecipientError.WrongGroup
import com.github.traderjoe95.mls.protocol.error.PrivateMessageRecipientError
import com.github.traderjoe95.mls.protocol.error.PrivateMessageSenderError
import com.github.traderjoe95.mls.protocol.error.ProcessMessageError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.WelcomeMessages
import com.github.traderjoe95.mls.protocol.group.prepareCommit
import com.github.traderjoe95.mls.protocol.message.GroupInfo.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.HandshakeMessage
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MessageOptions
import com.github.traderjoe95.mls.protocol.message.MlsHandshakeMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.ensureFormat
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.ensureFormatAndContent
import com.github.traderjoe95.mls.protocol.message.PrivateMessage
import com.github.traderjoe95.mls.protocol.message.UsePrivateMessage
import com.github.traderjoe95.mls.protocol.message.UsePublicMessage
import com.github.traderjoe95.mls.protocol.message.padding.randomized.CovertPadding
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.psk.PskLookup.Companion.delegatingTo
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafIndices
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.util.hex

class GroupClient<Identity : Any>(
  parent: MlsClient<Identity>,
  private val stateHistory: MutableList<GroupState>,
  private val authService: AuthenticationService<Identity>,
  var applicationMessageOptions: UsePrivateMessage = UsePrivateMessage(paddingStrategy = CovertPadding()),
  var handshakeMessageOptions: MessageOptions = UsePublicMessage,
) : PskLookup {
  companion object {
    fun <Identity : Any> newGroup(): Either<GroupCreationError, GroupClient<Identity>> = TODO()

    fun <Identity : Any> joinFromWelcome(): Either<WelcomeJoinError, GroupClient<Identity>> = TODO()

    fun <Identity : Any> joinFromExternal(): Either<ExternalJoinError, GroupClient<Identity>> = TODO()
  }

  val cipherSuite: CipherSuite
    get() = state.cipherSuite
  val groupId: GroupId
    get() = state.groupId
  val epoch: ULong
    get() = state.epoch
  val tree: PublicRatchetTree
    get() = state.tree.public
  val members: List<LeafNode<*>>
    get() = state.members
  val epochAuthenticator: Secret
    get() = state.keySchedule.epochAuthenticator

  private inline val state: GroupState
    get() = stateHistory.first()

  private val commitCache: MutableMap<String, CachedCommit> = mutableMapOf()

  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()
  private val psks: PskLookup = this delegatingTo parent

  suspend fun open(applicationMessage: ByteArray): Either<PrivateMessageRecipientError, ApplicationData> =
    either {
      val msg =
        decodeMessage(applicationMessage).bind()
          .ensureFormatAndContent<_, PrivateMessage<ApplicationData>>(
            WireFormat.MlsPrivateMessage,
            ContentType.Application,
          )

      getStateForEpoch(msg.message.groupId, msg.message.epoch)
        .ensureActive { msg.message.unprotect(this) }
        .content
        .content
    }

  suspend fun seal(
    data: ApplicationData,
    authenticatedData: ByteArray,
  ): Either<PrivateMessageSenderError, ByteArray> =
    either {
      state.ensureActive { messages.applicationMessage(data, applicationMessageOptions, authenticatedData) }
        .encodeUnsafe()
    }

  suspend fun process(handshakeMessage: ByteArray): Either<ProcessMessageError, WelcomeMessages?> =
    either {
      with(authService) {
        val msg: MlsHandshakeMessage =
          decodeMessage(handshakeMessage).bind()
            .ensureFormat<HandshakeMessage>(handshakeMessageOptions.wireFormat)

        val cached = commitCache[handshakeMessage.hex]

        val newState = state.ensureActive { process(msg, psks = psks, cachedState = cached?.newState) }

        when (newState.epoch) {
          epoch -> replaceCurrentState(newState)
          else -> advanceCurrentState(newState)
        }

        cached?.welcomeMessages
      }
    }

  suspend fun addMember(keyPackage: KeyPackage): Either<CreateAddError, ByteArray> =
    either {
      state.ensureActive { messages.add(keyPackage) }.encodeUnsafe()
    }

  suspend fun addMember(keyPackageBytes: ByteArray): Either<CreateAddError, ByteArray> =
    either {
      addMember(DecoderError.wrap { KeyPackage.decode(keyPackageBytes) }).bind()
    }

  suspend fun update(): Either<CreateUpdateError, ByteArray> =
    either {
      state.ensureActive { messages.update(updateLeafNode(cipherSuite.generateHpkeKeyPair())) }.encodeUnsafe()
    }

  suspend fun removeMember(memberIdx: UInt): Either<CreateRemoveError, ByteArray> =
    either {
      members.uSize.let {
        ensure(memberIdx < it) { CreateRemoveError.MemberIndexOutOfBounds(memberIdx, it) }
      }

      val memberLeafIdx = tree.nonBlankLeafIndices[memberIdx.toInt()]

      state.ensureActive { messages.remove(memberLeafIdx) }.encodeUnsafe()
    }

  suspend fun injectExternalPsk(pskId: ByteArray): Either<CreatePreSharedKeyError, ByteArray> =
    either {
      state.ensureActive { messages.preSharedKey(pskId, psks = psks) }.encodeUnsafe()
    }

  suspend fun injectResumptionPsk(epoch: ULong): Either<CreatePreSharedKeyError, ByteArray> =
    either {
      state.ensureActive { messages.preSharedKey(groupId, epoch, psks = psks) }.encodeUnsafe()
    }

  @JvmOverloads
  suspend fun commit(
    proposalFilter: (Proposal) -> Boolean = { true },
    additionalProposals: List<Proposal>,
  ): Either<SenderCommitError, ByteArray> =
    either {
      state.ensureActive {
        val proposalRefs =
          getStoredProposals()
            .sortedBy { it.received }
            .filter { proposalFilter(it.proposal) }
            .map { it.ref }

        with(authService) {
          val (newState, commitMsg, welcomeMsgs) =
            prepareCommit(proposalRefs + additionalProposals, handshakeMessageOptions, psks = psks)

          commitMsg.encodeUnsafe().also {
            commitCache[it.hex] = CachedCommit(newState, welcomeMsgs)
          }
        }
      }
    }

  fun groupInfo(): Either<GroupInfoError, ByteArray> =
    either {
      state.ensureActive { groupInfo(inlineTree = true, public = true) }.encodeUnsafe()
    }

  fun registerExternalPsk(
    pskId: ByteArray,
    psk: Secret,
  ): GroupClient<Identity> = apply { externalPsks[pskId.hex] = psk }

  fun deleteExternalPsk(pskId: ByteArray): GroupClient<Identity> = apply { externalPsks.remove(pskId.hex) }

  fun clearExternalPsks(): GroupClient<Identity> = apply { externalPsks.clear() }

  private fun decodeMessage(byteArray: ByteArray): Either<DecoderError, MlsMessage<*>> =
    either {
      DecoderError.wrap { MlsMessage.decode(byteArray) }
    }

  context(Raise<HistoryAccessError>)
  private fun getStateForEpoch(
    groupId: GroupId,
    epoch: ULong,
  ): GroupState {
    ensure(groupId eq this@GroupClient.groupId) { WrongGroup(groupId, this@GroupClient.groupId) }

    ensure(epoch <= this@GroupClient.epoch) { FutureEpoch(groupId, epoch, this@GroupClient.epoch) }

    return stateHistory
      .find { it.epoch == epoch }
      ?: raise(EpochNotAvailable(groupId, epoch))
  }

  private fun replaceCurrentState(newState: GroupState) {
    stateHistory[0] = newState
  }

  private fun advanceCurrentState(newState: GroupState) {
    stateHistory.add(0, newState)
    commitCache.clear()
  }

  private data class CachedCommit(
    val newState: GroupState,
    val welcomeMessages: WelcomeMessages,
  )

  context(Raise<PskError>)
  override suspend fun getPreSharedKey(id: PreSharedKeyId): Secret =
    when (id) {
      is ResumptionPskId ->
        recover(
          block = { getStateForEpoch(id.pskGroupId, id.pskEpoch) },
          recover = {
            when (it) {
              is EpochError -> raise(it)
              else -> raise(PskError.PskNotFound(id))
            }
          },
        ).keySchedule.resumptionPsk

      is ExternalPskId -> externalPsks[id.pskId.hex] ?: raise(PskError.PskNotFound(id))
    }
}