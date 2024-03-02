package com.github.traderjoe95.mls.protocol.client

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.left
import arrow.core.prependTo
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.recover
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.client.ProcessHandshakeResult.CommitProcessedWithNewMembers
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
import com.github.traderjoe95.mls.protocol.error.ReInitError
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.WelcomeMessages
import com.github.traderjoe95.mls.protocol.group.joinGroup
import com.github.traderjoe95.mls.protocol.group.joinGroupExternal
import com.github.traderjoe95.mls.protocol.group.prepareCommit
import com.github.traderjoe95.mls.protocol.group.resumption.resumeReInit
import com.github.traderjoe95.mls.protocol.message.GroupInfo
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
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.message.padding.randomized.CovertPadding
import com.github.traderjoe95.mls.protocol.psk.ExternalPskHolder
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.psk.PskLookup.Companion.delegatingTo
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
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

sealed class GroupClient<Identity : Any, State : GroupState>(
  internal val stateHistory: MutableList<GroupState>,
  internal val authService: AuthenticationService<Identity>,
  internal val parentPskLookup: PskLookup? = null,
) : PskLookup {
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

  val state: State
    get() = stateHistory.first().coerceState()

  protected val psks: PskLookup by lazy { this delegatingTo parentPskLookup }

  suspend fun open(applicationMessage: ByteArray): Either<PrivateMessageRecipientError, ApplicationData> =
    either {
      val msg =
        ActiveGroupClient.decodeMessage(applicationMessage).bind()
          .ensureFormatAndContent<_, PrivateMessage<ApplicationData>>(
            WireFormat.MlsPrivateMessage,
            ContentType.Application,
          )

      getStateForEpoch(msg.message.groupId, msg.message.epoch)
        .ensureActive { msg.message.unprotect(this) }
        .bind()
        .content
        .content
    }

  override suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret> =
    when (id) {
      is ResumptionPskId ->
        either { getStateForEpoch(id.pskGroupId, id.pskEpoch) }
          .recover {
            when (it) {
              is EpochError -> raise(it)
              else -> raise(PskError.PskNotFound(id))
            }
          }
          .flatMap {
            when (it) {
              is PskLookup -> it.getPreSharedKey(id)
              else -> PskError.PskNotFound(id).left()
            }
          }

      is ExternalPskId -> PskError.PskNotFound(id).left()
    }

  protected abstract fun GroupState.coerceState(): State

  context(Raise<HistoryAccessError>)
  protected fun getStateForEpoch(
    groupId: GroupId,
    epoch: ULong,
  ): GroupState {
    ensure(groupId eq this@GroupClient.groupId) { WrongGroup(groupId, this@GroupClient.groupId) }

    ensure(epoch <= this@GroupClient.epoch) { FutureEpoch(groupId, epoch, this@GroupClient.epoch) }

    return stateHistory
      .find { it.epoch == epoch }
      ?: raise(EpochNotAvailable(groupId, epoch))
  }

  protected fun replaceCurrentState(newState: GroupState) {
    stateHistory[0] = newState
  }

  protected open fun advanceCurrentState(newState: GroupState) {
    stateHistory.add(0, newState)
  }
}

class ActiveGroupClient<Identity : Any>(
  stateHistory: MutableList<GroupState>,
  authService: AuthenticationService<Identity>,
  var applicationMessageOptions: UsePrivateMessage = UsePrivateMessage(paddingStrategy = CovertPadding()),
  var handshakeMessageOptions: MessageOptions = UsePublicMessage,
  parentPskLookup: PskLookup? = null,
) : GroupClient<Identity, GroupState.Active>(stateHistory, authService, parentPskLookup),
  ExternalPskHolder<ActiveGroupClient<Identity>> {
  companion object {
    fun <Identity : Any> newGroup(
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      groupId: GroupId? = null,
      parentPskLookup: PskLookup = PskLookup.EMPTY,
    ): Either<GroupCreationError, ActiveGroupClient<Identity>> =
      com.github.traderjoe95.mls.protocol.group.newGroup(ownKeyPackage, groupId = groupId)
        .map { ActiveGroupClient(mutableListOf(it), authenticationService, parentPskLookup = parentPskLookup) }

    suspend fun <Identity : Any> joinFromWelcomeMessage(
      welcomeMessageBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      resumingFrom: GroupState? = null,
      optionalTree: PublicRatchetTree? = null,
      parentPskLookup: PskLookup = PskLookup.EMPTY,
    ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
      either {
        val msg = decodeMessage(welcomeMessageBytes).bind().ensureFormat<Welcome>()

        joinFromWelcome(
          msg.message,
          ownKeyPackage,
          authenticationService,
          resumingFrom,
          optionalTree,
          parentPskLookup,
        ).bind()
      }

    suspend fun <Identity : Any> joinFromWelcome(
      welcome: Welcome,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      resumingFrom: GroupState? = null,
      optionalTree: PublicRatchetTree? = null,
      parentPskLookup: PskLookup = PskLookup.EMPTY,
    ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
      either {
        val groupState =
          welcome.joinGroup(
            ownKeyPackage,
            authenticationService,
            psks = parentPskLookup,
            resumingFrom = resumingFrom,
            optionalTree = optionalTree,
          ).bind()

        ActiveGroupClient(
          mutableListOf(groupState),
          authenticationService,
          parentPskLookup = parentPskLookup,
        )
      }

    suspend fun <Identity : Any> joinFromGroupInfoMessage(
      groupInfoMessageBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      authenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
      parentPskLookup: PskLookup = PskLookup.EMPTY,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      either {
        val msg = decodeMessage(groupInfoMessageBytes).bind().ensureFormat<GroupInfo>()

        joinFromGroupInfo(
          msg.message,
          ownKeyPackage,
          authenticationService,
          authenticatedData,
          optionalTree,
          parentPskLookup,
        ).bind()
      }

    suspend fun <Identity : Any> joinFromGroupInfo(
      groupInfoBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      authenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
      parentPskLookup: PskLookup = PskLookup.EMPTY,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      either {
        val groupInfo = DecoderError.wrap { GroupInfo.decode(groupInfoBytes) }

        joinFromGroupInfo(
          groupInfo,
          ownKeyPackage,
          authenticationService,
          authenticatedData,
          optionalTree,
          parentPskLookup,
        ).bind()
      }

    suspend fun <Identity : Any> joinFromGroupInfo(
      groupInfo: GroupInfo,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      authenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
      parentPskLookup: PskLookup = PskLookup.EMPTY,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      either {
        val (groupState, commitMsg) =
          groupInfo.joinGroupExternal(
            ownKeyPackage,
            authenticationService,
            authenticatedData = authenticatedData,
            optionalTree = optionalTree,
          ).bind()

        ActiveGroupClient(
          mutableListOf(groupState),
          authenticationService,
          parentPskLookup = parentPskLookup,
        ) to commitMsg.encodeUnsafe()
      }

    internal fun decodeMessage(byteArray: ByteArray): Either<DecoderError, MlsMessage<*>> =
      either {
        DecoderError.wrap { MlsMessage.decode(byteArray) }
      }
  }

  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()
  private val commitCache: MutableMap<String, CachedCommit> = mutableMapOf()

  suspend fun seal(
    data: ApplicationData,
    authenticatedData: ByteArray,
  ): Either<PrivateMessageSenderError, ByteArray> =
    either {
      state.ensureActive { messages.applicationMessage(data, applicationMessageOptions, authenticatedData) }
        .bind()
        .encodeUnsafe()
    }

  suspend fun processHandshake(handshakeMessageBytes: ByteArray): Either<ProcessMessageError, ProcessHandshakeResult<Identity>> =
    either {
      with(authService) {
        val msg: MlsHandshakeMessage =
          decodeMessage(handshakeMessageBytes).bind()
            .ensureFormat<HandshakeMessage>(handshakeMessageOptions.wireFormat)

        val cached = commitCache[handshakeMessageBytes.hex]

        val newState =
          state.ensureActive {
            process(msg, authService, psks = psks, cachedState = cached?.newState)
          }.bind()

        when (newState.epoch) {
          epoch -> {
            replaceCurrentState(newState)
            ProcessHandshakeResult.ProposalReceived
          }

          else ->
            when (newState) {
              is GroupState.Active -> {
                advanceCurrentState(newState)
                cached?.welcomeMessages
                  ?.takeIf { it.isNotEmpty() }
                  ?.let(::CommitProcessedWithNewMembers)
                  ?: ProcessHandshakeResult.CommitProcessed
              }

              is GroupState.Suspended ->
                ProcessHandshakeResult.ReInitProcessed(SuspendedGroupClient(this@ActiveGroupClient, newState))
            }
        }
      }
    }

  suspend fun addMember(keyPackage: KeyPackage): Either<CreateAddError, ByteArray> =
    either {
      state.ensureActive { messages.add(keyPackage) }.bind().encodeUnsafe()
    }

  suspend fun addMember(keyPackageBytes: ByteArray): Either<CreateAddError, ByteArray> =
    either {
      addMember(DecoderError.wrap { KeyPackage.decode(keyPackageBytes) }).bind()
    }

  suspend fun update(): Either<CreateUpdateError, ByteArray> =
    either {
      state.ensureActive { messages.update(updateLeafNode(cipherSuite.generateHpkeKeyPair())) }.bind().encodeUnsafe()
    }

  suspend fun removeMember(memberIdx: UInt): Either<CreateRemoveError, ByteArray> =
    either {
      state.ensureActive { messages.remove(leafIndexFor(memberIdx).bind()) }.bind().encodeUnsafe()
    }

  suspend fun injectExternalPsk(pskId: ByteArray): Either<CreatePreSharedKeyError, ByteArray> =
    either {
      state.ensureActive { messages.preSharedKey(pskId, psks = psks) }.bind().encodeUnsafe()
    }

  suspend fun injectResumptionPsk(epoch: ULong): Either<CreatePreSharedKeyError, ByteArray> =
    either {
      state.ensureActive { messages.preSharedKey(groupId, epoch, psks = psks) }.bind().encodeUnsafe()
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
            prepareCommit(proposalRefs + additionalProposals, authService, handshakeMessageOptions, psks = psks).bind()

          commitMsg.encodeUnsafe().also {
            commitCache[it.hex] = CachedCommit(newState, welcomeMsgs)
          }
        }
      }
    }

  fun groupInfo(): Either<GroupInfoError, ByteArray> =
    either {
      state.ensureActive { groupInfo(inlineTree = true, public = true).bind() }.encodeUnsafe()
    }

  fun leafIndexFor(memberIdx: UInt): Either<CreateRemoveError.MemberIndexOutOfBounds, LeafIndex> =
    either {
      members.uSize.let {
        ensure(memberIdx < it) { CreateRemoveError.MemberIndexOutOfBounds(memberIdx, it) }
      }

      tree.nonBlankLeafIndices[memberIdx.toInt()]
    }

  override fun registerExternalPsk(
    pskId: ByteArray,
    psk: Secret,
  ): ActiveGroupClient<Identity> =
    apply {
      externalPsks[pskId.hex] = psk
    }

  override fun deleteExternalPsk(pskId: ByteArray): ActiveGroupClient<Identity> = apply { externalPsks.remove(pskId.hex) }

  override fun clearExternalPsks(): ActiveGroupClient<Identity> = apply { externalPsks.clear() }

  override suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret> =
    when (id) {
      is ResumptionPskId ->
        either { getStateForEpoch(id.pskGroupId, id.pskEpoch) }
          .recover {
            when (it) {
              is EpochError -> raise(it)
              else -> raise(PskError.PskNotFound(id))
            }
          }
          .flatMap {
            when (it) {
              is PskLookup -> it.getPreSharedKey(id)
              else -> PskError.PskNotFound(id).left()
            }
          }

      is ExternalPskId -> either { externalPsks[id.pskId.hex] ?: raise(PskError.PskNotFound(id)) }
    }

  override fun GroupState.coerceState(): GroupState.Active = coerceActive()

  override fun advanceCurrentState(newState: GroupState) {
    super.advanceCurrentState(newState)
    commitCache.clear()
  }

  private data class CachedCommit(
    val newState: GroupState,
    val welcomeMessages: WelcomeMessages,
  )
}

class SuspendedGroupClient<Identity : Any>(
  private val lastActiveState: ActiveGroupClient<Identity>,
  suspendedState: GroupState.Suspended,
) : GroupClient<Identity, GroupState.Suspended>(
    suspendedState.prependTo(lastActiveState.stateHistory).toMutableList(),
    lastActiveState.authService,
  ) {
  suspend fun resume(
    ownKeyPackage: KeyPackage.Private,
    otherKeyPackages: List<KeyPackage>,
  ): Either<ReInitError, Pair<ActiveGroupClient<Identity>, WelcomeMessages>> =
    either {
      val (newGroup, welcomeMessages) = state.resumeReInit(ownKeyPackage, otherKeyPackages, authService).bind()

      ActiveGroupClient(
        mutableListOf(newGroup),
        authService,
        lastActiveState.applicationMessageOptions,
        lastActiveState.handshakeMessageOptions,
        parentPskLookup = lastActiveState.parentPskLookup,
      ) to welcomeMessages
    }

  override fun GroupState.coerceState(): GroupState.Suspended = coerceSuspended()
}
