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
import com.github.traderjoe95.mls.protocol.error.BranchError
import com.github.traderjoe95.mls.protocol.error.CreateAddError
import com.github.traderjoe95.mls.protocol.error.CreatePreSharedKeyError
import com.github.traderjoe95.mls.protocol.error.CreateReInitError
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
import com.github.traderjoe95.mls.protocol.group.resumption.branchGroup
import com.github.traderjoe95.mls.protocol.group.resumption.resumeReInit
import com.github.traderjoe95.mls.protocol.group.resumption.triggerReInit
import com.github.traderjoe95.mls.protocol.message.ApplicationMessage
import com.github.traderjoe95.mls.protocol.message.GroupInfo
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
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.util.hex

sealed class GroupClient<Identity : Any, State : GroupState>(
  internal val stateHistory: MutableList<GroupState>,
  internal val authService: AuthenticationService<Identity>,
  internal val managedBy: MlsClient<Identity>? = null,
  internal val parentPskLookup: PskLookup? = managedBy,
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

  suspend fun open(applicationMessage: ByteArray): Either<PrivateMessageRecipientError, AuthenticatedContent<ApplicationData>> =
    either {
      val msg =
        decodeMessage(applicationMessage).bind()
          .ensureFormatAndContent<_, PrivateMessage<ApplicationData>>(
            WireFormat.MlsPrivateMessage,
            ContentType.Application,
          )

      open(msg.message).bind()
    }

  suspend fun open(applicationMessage: ApplicationMessage): Either<PrivateMessageRecipientError, AuthenticatedContent<ApplicationData>> =
    either {
      getStateForEpoch(applicationMessage.groupId, applicationMessage.epoch)
        .ensureActive { applicationMessage.unprotect(this) }
        .bind()
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
  internal fun getStateForEpoch(
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

  companion object {
    @JvmStatic
    fun <Identity : Any> newGroup(
      managedBy: MlsClient<Identity>,
      ownKeyPackage: KeyPackage.Private,
      groupId: GroupId? = null,
    ): Either<GroupCreationError, ActiveGroupClient<Identity>> =
      newGroup(ownKeyPackage, managedBy.authenticationService, groupId, managedBy)

    @JvmStatic
    fun <Identity : Any> newGroup(
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      groupId: GroupId? = null,
      managedBy: MlsClient<Identity>? = null,
      parentPskLookup: PskLookup? = managedBy,
    ): Either<GroupCreationError, ActiveGroupClient<Identity>> =
      JoiningGroupClient(ownKeyPackage, authenticationService, managedBy, parentPskLookup)
        .createNew(groupId)

    @JvmStatic
    suspend fun <Identity : Any> joinFromWelcomeMessage(
      managedBy: MlsClient<Identity>,
      welcomeMessageBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      resumingFrom: GroupState? = null,
      optionalTree: PublicRatchetTree? = null,
    ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
      joinFromWelcomeMessage(
        welcomeMessageBytes,
        ownKeyPackage,
        managedBy.authenticationService,
        resumingFrom,
        optionalTree,
        managedBy,
      )

    @JvmStatic
    suspend fun <Identity : Any> joinFromWelcomeMessage(
      welcomeMessageBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      resumingFrom: GroupState? = null,
      optionalTree: PublicRatchetTree? = null,
      managedBy: MlsClient<Identity>? = null,
      parentPskLookup: PskLookup? = managedBy,
    ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
      JoiningGroupClient(ownKeyPackage, authenticationService, managedBy, parentPskLookup)
        .processWelcomeMessage(welcomeMessageBytes, optionalTree, resumingFrom)

    @JvmStatic
    suspend fun <Identity : Any> joinFromWelcome(
      managedBy: MlsClient<Identity>,
      welcome: Welcome,
      ownKeyPackage: KeyPackage.Private,
      resumingFrom: GroupState? = null,
      optionalTree: PublicRatchetTree? = null,
    ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
      joinFromWelcome(
        welcome,
        ownKeyPackage,
        managedBy.authenticationService,
        resumingFrom,
        optionalTree,
        managedBy,
      )

    @JvmStatic
    suspend fun <Identity : Any> joinFromWelcome(
      welcome: Welcome,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      resumingFrom: GroupState? = null,
      optionalTree: PublicRatchetTree? = null,
      managedBy: MlsClient<Identity>? = null,
      parentPskLookup: PskLookup? = managedBy,
    ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
      JoiningGroupClient(ownKeyPackage, authenticationService, managedBy, parentPskLookup)
        .processWelcome(welcome, optionalTree, resumingFrom)

    @JvmStatic
    suspend fun <Identity : Any> joinFromGroupInfoMessage(
      managedBy: MlsClient<Identity>,
      groupInfoMessageBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      commitAuthenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      joinFromGroupInfoMessage(
        groupInfoMessageBytes,
        ownKeyPackage,
        managedBy.authenticationService,
        commitAuthenticatedData,
        optionalTree,
        managedBy,
      )

    @JvmStatic
    suspend fun <Identity : Any> joinFromGroupInfoMessage(
      groupInfoMessageBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      commitAuthenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
      managedBy: MlsClient<Identity>? = null,
      parentPskLookup: PskLookup? = managedBy,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      JoiningGroupClient(ownKeyPackage, authenticationService, managedBy, parentPskLookup)
        .processGroupInfoMessage(groupInfoMessageBytes, commitAuthenticatedData, optionalTree)

    @JvmStatic
    suspend fun <Identity : Any> joinFromGroupInfo(
      managedBy: MlsClient<Identity>,
      groupInfoBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      commitAuthenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      joinFromGroupInfo(
        groupInfoBytes,
        ownKeyPackage,
        managedBy.authenticationService,
        commitAuthenticatedData,
        optionalTree,
        managedBy,
      )

    @JvmStatic
    suspend fun <Identity : Any> joinFromGroupInfo(
      groupInfoBytes: ByteArray,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      commitAuthenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
      managedBy: MlsClient<Identity>? = null,
      parentPskLookup: PskLookup? = managedBy,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      JoiningGroupClient(ownKeyPackage, authenticationService, managedBy, parentPskLookup)
        .processGroupInfo(groupInfoBytes, commitAuthenticatedData, optionalTree)

    @JvmStatic
    suspend fun <Identity : Any> joinFromGroupInfo(
      managedBy: MlsClient<Identity>,
      groupInfo: GroupInfo,
      ownKeyPackage: KeyPackage.Private,
      commitAuthenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      joinFromGroupInfo(
        groupInfo,
        ownKeyPackage,
        managedBy.authenticationService,
        commitAuthenticatedData,
        optionalTree,
        managedBy,
      )

    @JvmStatic
    suspend fun <Identity : Any> joinFromGroupInfo(
      groupInfo: GroupInfo,
      ownKeyPackage: KeyPackage.Private,
      authenticationService: AuthenticationService<Identity>,
      commitAuthenticatedData: ByteArray = byteArrayOf(),
      optionalTree: PublicRatchetTree? = null,
      managedBy: MlsClient<Identity>? = null,
      parentPskLookup: PskLookup? = managedBy,
    ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
      JoiningGroupClient(
        ownKeyPackage,
        authenticationService,
        managedBy,
        parentPskLookup,
      ).processGroupInfo(groupInfo, commitAuthenticatedData, optionalTree)

    @JvmStatic
    internal fun decodeMessage(byteArray: ByteArray): Either<DecoderError, MlsMessage<*>> =
      either {
        DecoderError.wrap { MlsMessage.decode(byteArray) }
      }
  }
}

class JoiningGroupClient<Identity : Any> internal constructor(
  private val keyPackage: KeyPackage.Private,
  private val authService: AuthenticationService<Identity>,
  private val managedBy: MlsClient<Identity>? = null,
  private val pskLookup: PskLookup? = managedBy,
) : ExternalPskHolder<JoiningGroupClient<Identity>> {
  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()
  private val psks: PskLookup = this delegatingTo pskLookup

  fun createNew(groupId: GroupId? = null): Either<GroupCreationError, ActiveGroupClient<Identity>> =
    com.github.traderjoe95.mls.protocol.group.newGroup(keyPackage, groupId = groupId)
      .map {
        ActiveGroupClient(
          mutableListOf(it),
          authService,
          managedBy = managedBy,
          parentPskLookup = pskLookup,
        ).also { managedBy?.register(it) }
      }

  suspend fun processWelcomeMessage(
    messageBytes: ByteArray,
    optionalTree: PublicRatchetTree? = null,
    resumingFrom: GroupState? = null,
  ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
    either {
      val msg = GroupClient.decodeMessage(messageBytes).bind().ensureFormat<Welcome>(WireFormat.MlsWelcome)
      processWelcome(msg.message, optionalTree, resumingFrom).bind()
    }

  suspend fun processWelcome(
    welcome: Welcome,
    optionalTree: PublicRatchetTree? = null,
    resumingFrom: GroupState? = null,
  ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
    either {
      val groupState =
        welcome.joinGroup(
          keyPackage,
          authService,
          psks = psks,
          optionalTree = optionalTree,
          resumingFrom = resumingFrom,
        ).bind()

      ActiveGroupClient(
        mutableListOf(groupState),
        authService,
        managedBy = managedBy,
        parentPskLookup = pskLookup,
      ).also { managedBy?.register(it) }
    }

  suspend fun processGroupInfoMessage(
    messageBytes: ByteArray,
    commitAuthenticatedData: ByteArray = byteArrayOf(),
    optionalTree: PublicRatchetTree? = null,
  ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
    either {
      val msg = GroupClient.decodeMessage(messageBytes).bind().ensureFormat<GroupInfo>(WireFormat.MlsGroupInfo)
      processGroupInfo(msg.message, commitAuthenticatedData, optionalTree).bind()
    }

  suspend fun processGroupInfo(
    groupInfoBytes: ByteArray,
    commitAuthenticatedData: ByteArray = byteArrayOf(),
    optionalTree: PublicRatchetTree? = null,
  ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
    either {
      val groupInfo = DecoderError.wrap { GroupInfo.decode(groupInfoBytes) }

      processGroupInfo(groupInfo, commitAuthenticatedData, optionalTree).bind()
    }

  suspend fun processGroupInfo(
    groupInfo: GroupInfo,
    commitAuthenticatedData: ByteArray = byteArrayOf(),
    optionalTree: PublicRatchetTree? = null,
  ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
    either {
      val (groupState, commitMsg) =
        groupInfo.joinGroupExternal(
          keyPackage,
          authService,
          authenticatedData = commitAuthenticatedData,
          optionalTree = optionalTree,
        ).bind()

      ActiveGroupClient(
        mutableListOf(groupState),
        authService,
        managedBy = managedBy,
        parentPskLookup = pskLookup,
      ).also { managedBy?.register(it) } to commitMsg.encodeUnsafe()
    }

  override fun registerExternalPsk(
    pskId: ByteArray,
    psk: Secret,
  ): JoiningGroupClient<Identity> =
    apply {
      externalPsks[pskId.hex] = psk
    }

  override fun deleteExternalPsk(pskId: ByteArray): JoiningGroupClient<Identity> =
    apply { externalPsks.remove(pskId.hex) }

  override fun clearExternalPsks(): JoiningGroupClient<Identity> = apply { externalPsks.clear() }

  override suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret> =
    either {
      when (id) {
        is ExternalPskId -> externalPsks[id.pskId.hex] ?: raise(PskError.PskNotFound(id))
        is ResumptionPskId -> raise(PskError.PskNotFound(id))
      }
    }
}

class ActiveGroupClient<Identity : Any> internal constructor(
  stateHistory: MutableList<GroupState>,
  authService: AuthenticationService<Identity>,
  var applicationMessageOptions: UsePrivateMessage = UsePrivateMessage(paddingStrategy = CovertPadding()),
  var handshakeMessageOptions: MessageOptions = UsePublicMessage,
  managedBy: MlsClient<Identity>? = null,
  parentPskLookup: PskLookup? = managedBy,
) : GroupClient<Identity, GroupState.Active>(stateHistory, authService, managedBy, parentPskLookup),
  ExternalPskHolder<ActiveGroupClient<Identity>> {
  internal constructor(
    state: GroupState.Active,
    authService: AuthenticationService<Identity>,
    applicationMessageOptions: UsePrivateMessage = UsePrivateMessage(paddingStrategy = CovertPadding()),
    handshakeMessageOptions: MessageOptions = UsePublicMessage,
    managedBy: MlsClient<Identity>? = null,
    parentPskLookup: PskLookup? = managedBy,
  ) : this(
    mutableListOf(state),
    authService,
    applicationMessageOptions,
    handshakeMessageOptions,
    managedBy,
    parentPskLookup,
  )

  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()
  private val commitCache: MutableMap<String, CachedCommit> = mutableMapOf()

  suspend fun seal(
    data: ApplicationData,
    authenticatedData: ByteArray = byteArrayOf(),
  ): Either<PrivateMessageSenderError, ByteArray> =
    either {
      state.ensureActive { messages.applicationMessage(data, applicationMessageOptions, authenticatedData) }
        .bind()
        .encodeUnsafe()
    }

  suspend fun processHandshake(handshakeMessageBytes: ByteArray): Either<ProcessMessageError, ProcessHandshakeResult<Identity>> =
    either {
      val msg: MlsHandshakeMessage =
        decodeMessage(handshakeMessageBytes).bind()
          .ensureFormat<HandshakeMessage>(handshakeMessageOptions.wireFormat)

      processHandshake(msg.message).bind()
    }

  suspend fun processHandshake(handshakeMessage: HandshakeMessage): Either<ProcessMessageError, ProcessHandshakeResult<Identity>> =
    either {
      with(authService) {
        val cached = commitCache[makeCommitRef(handshakeMessage).hex]

        val newState =
          state.ensureActive {
            process(handshakeMessage, authService, psks = psks, cachedState = cached?.newState)
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
      state.messages
        .add(keyPackage, handshakeMessageOptions)
        .bind()
        .encodeUnsafe()
    }

  suspend fun addMember(keyPackageBytes: ByteArray): Either<CreateAddError, ByteArray> =
    either {
      addMember(DecoderError.wrap { KeyPackage.decode(keyPackageBytes) }).bind()
    }

  suspend fun update(): Either<CreateUpdateError, ByteArray> =
    either {
      state.messages
        .update(state.updateLeafNode(cipherSuite.generateHpkeKeyPair()), handshakeMessageOptions)
        .bind()
        .encodeUnsafe()
    }

  suspend fun removeMember(memberIdx: UInt): Either<CreateRemoveError, ByteArray> =
    either {
      state.messages
        .remove(leafIndexFor(memberIdx).bind(), handshakeMessageOptions)
        .bind()
        .encodeUnsafe()
    }

  suspend fun injectExternalPsk(pskId: ByteArray): Either<CreatePreSharedKeyError, ByteArray> =
    either {
      state.messages
        .preSharedKey(pskId, psks = psks, options = handshakeMessageOptions)
        .bind()
        .encodeUnsafe()
    }

  suspend fun injectResumptionPsk(epoch: ULong, groupId: GroupId = this.groupId): Either<CreatePreSharedKeyError, ByteArray> =
    either {
      state.messages
        .preSharedKey(groupId, epoch, psks = psks, options = handshakeMessageOptions)
        .bind()
        .encodeUnsafe()
    }

  suspend fun proposeReInit(
    newCipherSuite: CipherSuite,
    newExtensions: List<GroupContextExtension<*>> = state.extensions,
    newGroupId: GroupId? = null,
  ): Either<CreateReInitError, ByteArray> =
    either {
      state.messages
        .reInit(newCipherSuite, extensions = newExtensions, groupId = newGroupId, options = handshakeMessageOptions)
        .bind()
        .encodeUnsafe()
    }

  @JvmOverloads
  suspend fun commit(
    additionalProposals: List<Proposal> = listOf(),
    proposalFilter: (Proposal) -> Boolean = { true },
  ): Either<SenderCommitError, ByteArray> =
    either {
      val proposalRefs =
        state.getStoredProposals()
          .sortedBy { it.received }
          .filter { proposalFilter(it.proposal) }
          .map { it.ref }

      val (newState, commitMsg, welcomeMsgs) =
        state.prepareCommit(proposalRefs + additionalProposals, authService, handshakeMessageOptions, psks = psks)
          .bind()

      commitMsg.encodeUnsafe().also {
        commitCache[makeCommitRef(commitMsg.message).hex] = CachedCommit(newState, welcomeMsgs)
      }
    }

  suspend fun branch(
    ownKeyPackage: KeyPackage.Private,
    otherMembers: List<KeyPackage>,
    groupId: GroupId? = null,
  ): Either<BranchError, Pair<ActiveGroupClient<Identity>, WelcomeMessages>> =
    either {
      val (branchedGroup, welcome) =
        state.branchGroup(ownKeyPackage, otherMembers, authService, groupId = groupId).bind()

      ActiveGroupClient(
        branchedGroup,
        authService,
        applicationMessageOptions,
        handshakeMessageOptions,
        managedBy,
        parentPskLookup,
      ).also { managedBy?.register(it) } to welcome
    }

  suspend fun triggerReInit(
    newCipherSuite: CipherSuite,
    newExtensions: List<GroupContextExtension<*>> = state.extensions,
    newGroupId: GroupId? = null,
  ): Either<ReInitError, ByteArray> =
    state.triggerReInit(
      authService,
      groupId = newGroupId,
      cipherSuite = newCipherSuite,
      extensions = newExtensions,
      messageOptions = handshakeMessageOptions
    ).map { (suspendedGroup, commitMsg) ->
      commitMsg.encodeUnsafe().also {
        commitCache[makeCommitRef(commitMsg.message).hex] = CachedCommit(suspendedGroup, listOf())
      }
    }

  fun groupInfo(): Either<GroupInfoError, GroupInfo> =
    either {
      state.groupInfo(inlineTree = true, public = true).bind()
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

  override fun deleteExternalPsk(pskId: ByteArray): ActiveGroupClient<Identity> =
    apply { externalPsks.remove(pskId.hex) }

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

  private fun makeCommitRef(commit: HandshakeMessage): HashReference = cipherSuite.refHash("CommitRef", commit.encoded)

  private data class CachedCommit(
    val newState: GroupState,
    val welcomeMessages: WelcomeMessages,
  )
}

class SuspendedGroupClient<Identity : Any> internal constructor(
  private val lastActiveState: ActiveGroupClient<Identity>,
  suspendedState: GroupState.Suspended,
) : GroupClient<Identity, GroupState.Suspended>(
  suspendedState.prependTo(lastActiveState.stateHistory).toMutableList(),
  lastActiveState.authService,
  managedBy = lastActiveState.managedBy,
  parentPskLookup = null,
) {
  init {
    lastActiveState.managedBy?.register(this)
  }

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
        managedBy,
        parentPskLookup = lastActiveState.parentPskLookup,
      ).also { managedBy?.register(it) } to welcomeMessages
    }

  override fun GroupState.coerceState(): GroupState.Suspended = coerceSuspended()
}
