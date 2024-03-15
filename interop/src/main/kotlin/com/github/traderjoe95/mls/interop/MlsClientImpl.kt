package com.github.traderjoe95.mls.interop

import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.interop.proto.AddExternalSignerRequest
import com.github.traderjoe95.mls.interop.proto.AddProposalRequest
import com.github.traderjoe95.mls.interop.proto.CommitRequest
import com.github.traderjoe95.mls.interop.proto.CommitResponse
import com.github.traderjoe95.mls.interop.proto.CreateBranchRequest
import com.github.traderjoe95.mls.interop.proto.CreateExternalSignerRequest
import com.github.traderjoe95.mls.interop.proto.CreateExternalSignerResponse
import com.github.traderjoe95.mls.interop.proto.CreateGroupRequest
import com.github.traderjoe95.mls.interop.proto.CreateGroupResponse
import com.github.traderjoe95.mls.interop.proto.CreateKeyPackageRequest
import com.github.traderjoe95.mls.interop.proto.CreateKeyPackageResponse
import com.github.traderjoe95.mls.interop.proto.CreateSubgroupResponse
import com.github.traderjoe95.mls.interop.proto.ExportRequest
import com.github.traderjoe95.mls.interop.proto.ExportResponse
import com.github.traderjoe95.mls.interop.proto.ExternalJoinRequest
import com.github.traderjoe95.mls.interop.proto.ExternalJoinResponse
import com.github.traderjoe95.mls.interop.proto.ExternalPSKProposalRequest
import com.github.traderjoe95.mls.interop.proto.ExternalSignerProposalRequest
import com.github.traderjoe95.mls.interop.proto.FreeRequest
import com.github.traderjoe95.mls.interop.proto.FreeResponse
import com.github.traderjoe95.mls.interop.proto.GroupContextExtensionsProposalRequest
import com.github.traderjoe95.mls.interop.proto.GroupInfoRequest
import com.github.traderjoe95.mls.interop.proto.GroupInfoResponse
import com.github.traderjoe95.mls.interop.proto.HandleBranchRequest
import com.github.traderjoe95.mls.interop.proto.HandleBranchResponse
import com.github.traderjoe95.mls.interop.proto.HandleCommitRequest
import com.github.traderjoe95.mls.interop.proto.HandleCommitResponse
import com.github.traderjoe95.mls.interop.proto.HandlePendingCommitRequest
import com.github.traderjoe95.mls.interop.proto.HandleReInitCommitResponse
import com.github.traderjoe95.mls.interop.proto.HandleReInitWelcomeRequest
import com.github.traderjoe95.mls.interop.proto.JoinGroupRequest
import com.github.traderjoe95.mls.interop.proto.JoinGroupResponse
import com.github.traderjoe95.mls.interop.proto.NameRequest
import com.github.traderjoe95.mls.interop.proto.NameResponse
import com.github.traderjoe95.mls.interop.proto.NewMemberAddProposalRequest
import com.github.traderjoe95.mls.interop.proto.NewMemberAddProposalResponse
import com.github.traderjoe95.mls.interop.proto.ProposalResponse
import com.github.traderjoe95.mls.interop.proto.ProtectRequest
import com.github.traderjoe95.mls.interop.proto.ProtectResponse
import com.github.traderjoe95.mls.interop.proto.ReInitProposalRequest
import com.github.traderjoe95.mls.interop.proto.ReInitWelcomeRequest
import com.github.traderjoe95.mls.interop.proto.RemoveProposalRequest
import com.github.traderjoe95.mls.interop.proto.ResumptionPSKProposalRequest
import com.github.traderjoe95.mls.interop.proto.StateAuthRequest
import com.github.traderjoe95.mls.interop.proto.StateAuthResponse
import com.github.traderjoe95.mls.interop.proto.StorePSKRequest
import com.github.traderjoe95.mls.interop.proto.StorePSKResponse
import com.github.traderjoe95.mls.interop.proto.SupportedCiphersuitesRequest
import com.github.traderjoe95.mls.interop.proto.SupportedCiphersuitesResponse
import com.github.traderjoe95.mls.interop.proto.UnprotectRequest
import com.github.traderjoe95.mls.interop.proto.UnprotectResponse
import com.github.traderjoe95.mls.interop.proto.UpdateProposalRequest
import com.github.traderjoe95.mls.interop.proto.VertxMLSClientGrpcServer
import com.github.traderjoe95.mls.interop.proto.commitResponse
import com.github.traderjoe95.mls.interop.proto.createExternalSignerResponse
import com.github.traderjoe95.mls.interop.proto.createGroupResponse
import com.github.traderjoe95.mls.interop.proto.createKeyPackageResponse
import com.github.traderjoe95.mls.interop.proto.createSubgroupResponse
import com.github.traderjoe95.mls.interop.proto.exportResponse
import com.github.traderjoe95.mls.interop.proto.externalJoinResponse
import com.github.traderjoe95.mls.interop.proto.groupInfoResponse
import com.github.traderjoe95.mls.interop.proto.handleBranchResponse
import com.github.traderjoe95.mls.interop.proto.handleCommitResponse
import com.github.traderjoe95.mls.interop.proto.handleReInitCommitResponse
import com.github.traderjoe95.mls.interop.proto.joinGroupResponse
import com.github.traderjoe95.mls.interop.proto.newMemberAddProposalResponse
import com.github.traderjoe95.mls.interop.proto.protectResponse
import com.github.traderjoe95.mls.interop.proto.stateAuthResponse
import com.github.traderjoe95.mls.interop.proto.storePSKResponse
import com.github.traderjoe95.mls.interop.proto.supportedCiphersuitesResponse
import com.github.traderjoe95.mls.interop.proto.unprotectResponse
import com.github.traderjoe95.mls.interop.store.StateStore
import com.github.traderjoe95.mls.interop.store.StoredState
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.group.joinGroup
import com.github.traderjoe95.mls.protocol.group.joinGroupExternal
import com.github.traderjoe95.mls.protocol.group.newGroup
import com.github.traderjoe95.mls.protocol.group.resumption.branchGroup
import com.github.traderjoe95.mls.protocol.group.resumption.resumeReInit
import com.github.traderjoe95.mls.protocol.message.Messages.externalProposalMessage
import com.github.traderjoe95.mls.protocol.message.Messages.newMemberProposalMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.ensureFormatAndContent
import com.github.traderjoe95.mls.protocol.message.UsePrivateMessage
import com.github.traderjoe95.mls.protocol.message.UsePublicMessage
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.ExternalSenders
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.GroupId.Companion.asGroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteString
import io.vertx.core.Future
import io.vertx.core.Promise
import io.vertx.core.Vertx
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class MlsClientImpl(vertx: Vertx) :
  VertxMLSClientGrpcServer.MLSClientApi,
  CoroutineScope by CoroutineScope(vertx.dispatcher() + SupervisorJob()) {
  private val stateStore = StateStore()

  override fun name(request: NameRequest): Future<NameResponse> =
    Future.succeededFuture(NameResponse.newBuilder().setName("mls-kotlin").build())

  override fun supportedCiphersuites(request: SupportedCiphersuitesRequest): Future<SupportedCiphersuitesResponse> =
    Future.succeededFuture(
      supportedCiphersuitesResponse {
        ciphersuites.addAll(CipherSuite.VALID.map { it.toInt() })
      },
    )

  override fun createGroup(request: CreateGroupRequest): Future<CreateGroupResponse> =
    launchFuture {
      val groupId = GroupId(request.groupId.toByteArray())
      val cipherSuite =
        CipherSuite(request.cipherSuite.toUShort())
          ?: invalidArgument("Unsupported Cipher Suite ${request.cipherSuite}")
      val handshakeOptions = if (request.encryptHandshake) UsePrivateMessage() else UsePublicMessage
      val credential = BasicCredential(request.identity.toByteArray())

      val keyPackage = newKeyPackage(cipherSuite, credential).bind()

      val newGroup = newGroup(keyPackage, groupId = groupId).bind()

      createGroupResponse {
        stateId = stateStore.storeState(newGroup, handshakeOptions)
      }
    }

  override fun createKeyPackage(request: CreateKeyPackageRequest): Future<CreateKeyPackageResponse> =
    launchFuture {
      val cipherSuite =
        CipherSuite(request.cipherSuite.toUShort())
          ?: invalidArgument("Unsupported Cipher Suite ${request.cipherSuite}")
      val credential = BasicCredential(request.identity.toByteArray())

      val privateKeyPackage = newKeyPackage(cipherSuite, credential).bind()

      createKeyPackageResponse {
        keyPackage = MlsMessage(privateKeyPackage.public).encoded.toByteString()
        initPriv = privateKeyPackage.initPrivateKey.toByteString()
        encryptionPriv = privateKeyPackage.encPrivateKey.toByteString()
        signaturePriv = privateKeyPackage.signaturePrivateKey.toByteString()
        transactionId = stateStore.storeTransaction(privateKeyPackage)
      }
    }

  override fun joinGroup(request: JoinGroupRequest): Future<JoinGroupResponse> =
    launchFuture {
      val transaction =
        stateStore.getTransactionOrNull(request.transactionId)
          ?: error("transaction_id ${request.transactionId} is unknown")
      val welcome = request.welcome.decodeWelcome()
      val handshakeOptions = if (request.encryptHandshake) UsePrivateMessage() else UsePublicMessage
      val ratchetTree = request.ratchetTree.toByteArray().takeIf { it.isNotEmpty() }?.decodeAs(PublicRatchetTree.T)

      val joinedGroup =
        welcome.joinGroup(transaction.keyPackage, AuthService, psks = transaction, optionalTree = ratchetTree).bind()

      joinGroupResponse {
        epochAuthenticator = joinedGroup.keySchedule.epochAuthenticator.toByteString()
        stateId = stateStore.storeState(joinedGroup, handshakeOptions)
      }
    }

  override fun externalJoin(request: ExternalJoinRequest): Future<ExternalJoinResponse> =
    launchFuture {
      val groupInfo = request.groupInfo.decodeGroupInfo()
      val handshakeOptions = if (request.encryptHandshake) UsePrivateMessage() else UsePublicMessage
      val ratchetTree = request.ratchetTree.toByteArray().takeIf { it.isNotEmpty() }?.decodeAs(PublicRatchetTree.T)
      val credential = BasicCredential(request.identity.toByteArray())

      val (joinedGroup, commitMessage) =
        groupInfo.joinGroupExternal(
          newKeyPackage(groupInfo.cipherSuite, credential).bind(),
          AuthService,
          resync = request.removePrior,
          addPsks = request.psksList.map { it.toResolvedPsk(groupInfo.cipherSuite) },
          optionalTree = ratchetTree,
        ).bind()

      externalJoinResponse {
        stateId = stateStore.storeState(joinedGroup, handshakeOptions)
        commit = commitMessage.encoded.toByteString()
        epochAuthenticator = joinedGroup.keySchedule.epochAuthenticator.toByteString()
      }
    }

  override fun groupInfo(request: GroupInfoRequest): Future<GroupInfoResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)
      val info =
        state.groupState.ensureActive {
          groupInfo(inlineTree = !request.externalTree, public = true)
        }.bind()

      groupInfoResponse {
        groupInfo = info.encoded.toByteString()
        ratchetTree = if (request.externalTree) state.groupState.tree.encoded.toByteString() else ByteString.empty()
      }
    }

  override fun stateAuth(request: StateAuthRequest): Future<StateAuthResponse> =
    launchFuture<Nothing, _> {
      val state = stateStore.getState(request.stateId)

      stateAuthResponse { stateAuthSecret = state.groupState.keySchedule.epochAuthenticator.toByteString() }
    }

  override fun export(request: ExportRequest): Future<ExportResponse> =
    launchFuture<Nothing, _> {
      val state = stateStore.getState(request.stateId)
      val exported =
        state.groupState.keySchedule.mlsExporter(
          request.label,
          request.context.toByteArray(),
          request.keyLength.toUShort(),
        )

      exportResponse { exportedSecret = exported.toByteString() }
    }

  override fun protect(request: ProtectRequest): Future<ProtectResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)
      val protected =
        state.groupState.ensureActive {
          messages.applicationMessage(
            ApplicationData(request.plaintext.toByteArray()),
            authenticatedData = request.authenticatedData.toByteArray(),
          )
        }.bind()

      protectResponse { ciphertext = protected.encoded.toByteString() }
    }

  override fun unprotect(request: UnprotectRequest): Future<UnprotectResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      val content =
        MlsMessage.decode(request.ciphertext.toByteArray())
          .ensureFormatAndContent(WireFormat.MlsPrivateMessage, ContentType.Application)
          .message
          .unprotect(state.groupState.ensureActive())
          .bind()
          .framedContent

      unprotectResponse {
        authenticatedData = content.authenticatedData.toByteString()
        plaintext = content.content.toByteString()
      }
    }

  override fun storePSK(request: StorePSKRequest): Future<StorePSKResponse> =
    launchFuture<Nothing, _> {
      val stateOrTransaction =
        stateStore.getTransactionOrNull(request.stateOrTransactionId)
          ?: stateStore.getStateOrNull(request.stateOrTransactionId)
          ?: error("state_or_transaction_id ${request.stateOrTransactionId} is unknown")
      stateOrTransaction.addExternalPsk(request.pskId.toByteArray(), request.pskSecret.toByteArray().asSecret)

      storePSKResponse {}
    }

  override fun addProposal(request: AddProposalRequest): Future<ProposalResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)
      val keyPackage = request.keyPackage.decodeKeyPackage()

      state.groupState
        .ensureActive { messages.add(keyPackage, state.handshakeOptions) }
        .bind()
        .asProposalResponse()
    }

  override fun updateProposal(request: UpdateProposalRequest): Future<ProposalResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      state.groupState
        .ensureActive {
          messages.update(
            updateLeafNode(state.groupState.cipherSuite.generateHpkeKeyPair()),
            state.handshakeOptions,
          )
        }
        .bind()
        .asProposalResponse()
    }

  override fun removeProposal(request: RemoveProposalRequest): Future<ProposalResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      val removed = state.groupState.tree.findMember(request.removedId.toByteArray())

      state.groupState
        .ensureActive { messages.remove(removed, state.handshakeOptions) }
        .bind()
        .asProposalResponse()
    }

  override fun externalPSKProposal(request: ExternalPSKProposalRequest): Future<ProposalResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      state.groupState
        .ensureActive { messages.preSharedKey(request.pskId.toByteArray(), options = state.handshakeOptions) }
        .bind()
        .asProposalResponse()
    }

  override fun resumptionPSKProposal(request: ResumptionPSKProposalRequest): Future<ProposalResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      state.groupState
        .ensureActive {
          messages.preSharedKey(
            state.groupState.groupId,
            request.epochId.toULong(),
            options = state.handshakeOptions,
          )
        }
        .bind()
        .asProposalResponse()
    }

  override fun groupContextExtensionsProposal(request: GroupContextExtensionsProposalRequest): Future<ProposalResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      val extensions =
        request.extensionsList
          .map { it.toExtension() }

      state.groupState
        .ensureActive { messages.groupContextExtensions(extensions, options = state.handshakeOptions) }
        .bind()
        .asProposalResponse()
    }

  override fun commit(request: CommitRequest): Future<CommitResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      val (newGroupState, commit, welcomeMsgs) = request.createCommit(state)

      // Store pending commit
      state.pendingCommit = commit.encoded to stateStore.storeState(newGroupState, state.handshakeOptions)

      commitResponse {
        this.commit = commit.encoded.toByteString()
        welcome = welcomeMsgs.firstOrNull()?.welcome?.encoded?.toByteString() ?: ByteString.empty()
        ratchetTree = newGroupState.tree.takeIf { request.externalTree }?.encoded?.toByteString() ?: ByteString.empty()
      }
    }

  override fun handleCommit(request: HandleCommitRequest): Future<HandleCommitResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      if (state.pendingCommit?.first.contentEquals(request.commit.toByteArray())) {
        state.handlePendingCommit()
      } else {
        val newGroupState = request.processCommit(state)

        handleCommitResponse {
          stateId = stateStore.storeState(newGroupState, state.handshakeOptions)
          epochAuthenticator = newGroupState.keySchedule.epochAuthenticator.toByteString()
        }
      }
    }

  override fun handlePendingCommit(request: HandlePendingCommitRequest): Future<HandleCommitResponse> =
    launchFuture<Nothing, _> {
      stateStore.getState(request.stateId).handlePendingCommit()
    }

  private fun StoredState.handlePendingCommit(): HandleCommitResponse =
    handleCommitResponse {
      stateStore.getState(pendingCommit?.second ?: invalidArgument("No pending commit in state $id")).apply {
        stateId = id
        epochAuthenticator = groupState.keySchedule.epochAuthenticator.toByteString()
      }
    }

  override fun reInitProposal(request: ReInitProposalRequest): Future<ProposalResponse> =
    launchFuture {
      stateStore.getState(request.stateId).groupState.ensureActive {
        messages.reInit(
          CipherSuite(request.cipherSuite.toUShort())
            ?: invalidArgument("Unsupported Cipher Suite ${request.cipherSuite}"),
          groupId = request.groupId.toByteArray().asGroupId,
          extensions = request.extensionsList.map { it.toExtension() },
        )
      }.bind().asProposalResponse()
    }

  override fun reInitCommit(request: CommitRequest): Future<CommitResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      val (newGroupState, commit, _) = request.createCommit(state)

      val suspended = newGroupState.ensureSuspended()
      val newKp =
        newKeyPackage(
          suspended.reInit.cipherSuite,
          newGroupState.tree.leafNode(newGroupState.leafIndex).credential as BasicCredential,
        ).bind()

      // Store pending reinit
      state.pendingCommit = commit.encoded to stateStore.storeReInit(suspended, newKp, state.handshakeOptions)

      commitResponse {
        this.commit = commit.encoded.toByteString()
        welcome = ByteString.empty()
        ratchetTree = newGroupState.tree.takeIf { request.externalTree }?.encoded?.toByteString() ?: ByteString.empty()
      }
    }

  override fun handlePendingReInitCommit(request: HandlePendingCommitRequest): Future<HandleReInitCommitResponse> =
    launchFuture<Nothing, _> {
      val state = stateStore.getState(request.stateId)

      state.handlePendingReInitCommit()
    }

  override fun handleReInitCommit(request: HandleCommitRequest): Future<HandleReInitCommitResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      if (state.pendingCommit?.first.contentEquals(request.commit.toByteArray())) {
        state.handlePendingReInitCommit()
      } else {
        val newGroupState = request.processCommit(state)

        val suspended = newGroupState.ensureSuspended()
        val newKp =
          newKeyPackage(
            suspended.reInit.cipherSuite,
            newGroupState.tree.leafNode(newGroupState.leafIndex).credential as BasicCredential,
          ).bind()

        handleReInitCommitResponse {
          reinitId = stateStore.storeReInit(suspended, newKp, state.handshakeOptions)
          keyPackage = MlsMessage(newKp.public).encoded.toByteString()
          epochAuthenticator = suspended.keySchedule.epochAuthenticator.toByteString()
        }
      }
    }

  private fun StoredState.handlePendingReInitCommit(): HandleReInitCommitResponse =
    handleReInitCommitResponse {
      stateStore.getReInit(pendingCommit?.second ?: invalidArgument("No pending commit in state $id")).apply {
        reinitId = id
        this@handleReInitCommitResponse.keyPackage = MlsMessage(keyPackage.public).encoded.toByteString()
        epochAuthenticator = oldGroup.keySchedule.epochAuthenticator.toByteString()
      }
    }

  override fun reInitWelcome(request: ReInitWelcomeRequest): Future<CreateSubgroupResponse> =
    launchFuture {
      val reInit = stateStore.getReInit(request.reinitId)

      val keyPackages = request.keyPackageList.map { it.decodeKeyPackage() }

      val (newGroup, welcomeMsgs) =
        reInit.oldGroup.resumeReInit(
          reInit.keyPackage,
          keyPackages,
          AuthService,
          forcePath = request.forcePath,
          inlineTree = !request.externalTree,
        ).bind()

      createSubgroupResponse {
        stateId = stateStore.storeState(newGroup, reInit.handshakeOptions)
        welcome = welcomeMsgs.firstOrNull()?.welcome?.encoded?.toByteString() ?: ByteString.empty()
        ratchetTree = newGroup.tree.takeIf { request.externalTree }?.encoded?.toByteString() ?: ByteString.empty()
        epochAuthenticator = newGroup.keySchedule.epochAuthenticator.toByteString()
      }
    }

  override fun handleReInitWelcome(request: HandleReInitWelcomeRequest): Future<JoinGroupResponse> =
    launchFuture {
      val reInit = stateStore.getReInit(request.reinitId)
      val welcome = request.welcome.decodeWelcome()

      val joinedGroup =
        welcome.joinGroup(
          reInit.keyPackage,
          AuthService,
          resumingFrom = reInit.oldGroup,
          psks = reInit.oldGroup,
        ).bind()

      joinGroupResponse {
        stateId = stateStore.storeState(joinedGroup, reInit.handshakeOptions)
        epochAuthenticator = joinedGroup.keySchedule.epochAuthenticator.toByteString()
      }
    }

  override fun createBranch(request: CreateBranchRequest): Future<CreateSubgroupResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      val newKp =
        newKeyPackage(
          state.groupState.cipherSuite,
          state.groupState.tree.leafNode(state.groupState.leafIndex).credential as BasicCredential,
        ).bind()

      val (branched, welcomeMsgs) =
        state.groupState.ensureActive().branchGroup(
          newKp,
          request.keyPackagesList.map { it.decodeKeyPackage() },
          AuthService,
          groupId = request.groupId.toByteArray().asGroupId,
          extensions = request.extensionsList.map { it.toExtension() },
          inlineTree = !request.externalTree,
          forcePath = request.forcePath,
        ).bind()

      createSubgroupResponse {
        stateId = stateStore.storeState(branched, state.handshakeOptions)
        welcome = welcomeMsgs.firstOrNull()?.welcome?.encoded?.toByteString() ?: ByteString.empty()
        ratchetTree = branched.tree.takeIf { request.externalTree }?.encoded?.toByteString() ?: ByteString.empty()
        epochAuthenticator = branched.keySchedule.epochAuthenticator.toByteString()
      }
    }

  override fun handleBranch(request: HandleBranchRequest): Future<HandleBranchResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)
      val transaction = stateStore.getTransaction(request.transactionId)

      val welcome = request.welcome.decodeWelcome()

      val joinedGroup =
        welcome.joinGroup(
          transaction.keyPackage,
          AuthService,
          resumingFrom = state.groupState,
          psks = state.groupState.ensureActive(),
        ).bind()

      handleBranchResponse {
        stateId = stateStore.storeState(joinedGroup, state.handshakeOptions)
        epochAuthenticator = joinedGroup.keySchedule.epochAuthenticator.toByteString()
      }
    }

  override fun newMemberAddProposal(request: NewMemberAddProposalRequest): Future<NewMemberAddProposalResponse> =
    launchFuture {
      val groupInfo = request.groupInfo.decodeGroupInfo()
      val keyPackage =
        newKeyPackage(
          groupInfo.cipherSuite,
          BasicCredential(request.identity.toByteArray()),
        ).bind()

      val newMemberAdd = newMemberProposalMessage(keyPackage, groupInfo.groupContext).bind()

      newMemberAddProposalResponse {
        transactionId = stateStore.storeTransaction(keyPackage)
        proposal = newMemberAdd.encoded.toByteString()
        initPriv = keyPackage.initPrivateKey.toByteString()
        encryptionPriv = keyPackage.encPrivateKey.toByteString()
        signaturePriv = keyPackage.signaturePrivateKey.toByteString()
      }
    }

  override fun createExternalSigner(request: CreateExternalSignerRequest): Future<CreateExternalSignerResponse> =
    launchFuture {
      val cipherSuite =
        CipherSuite(request.cipherSuite.toUShort())
          ?: invalidArgument("Unsupported Cipher Suite ${request.cipherSuite}")
      val keyPair = cipherSuite.generateSignatureKeyPair()

      val credential = BasicCredential(request.identity.toByteArray())
      val externalSigner = ExternalSenders.ExternalSender(keyPair.public, credential)

      createExternalSignerResponse {
        signerId = stateStore.storeSigner(keyPair, credential)
        externalSender = ExternalSenders.ExternalSender.T.encode(externalSigner).toByteString()
      }
    }

  override fun addExternalSigner(request: AddExternalSignerRequest): Future<ProposalResponse> =
    launchFuture {
      val state = stateStore.getState(request.stateId)

      state.groupState
        .ensureActive {
          val externalSender =
            DecoderError.wrap { request.externalSender.toByteArray().decodeAs(ExternalSenders.ExternalSender.T) }

          val extensions = extensions
          val externalSenders =
            groupContext.extension<ExternalSenders>()?.plus(externalSender)
              ?: ExternalSenders(externalSender)

          val newExtensions = extensions.filter { it !is ExternalSenders } + externalSenders

          messages.groupContextExtensions(newExtensions, state.handshakeOptions)
        }
        .bind()
        .asProposalResponse()
    }

  override fun externalSignerProposal(request: ExternalSignerProposalRequest): Future<ProposalResponse> =
    launchFuture {
      val signer = stateStore.getSigner(request.signerId)
      val groupInfo = request.groupInfo.decodeGroupInfo()
      val tree = request.ratchetTree.toByteArray().decodeAs(PublicRatchetTree.T)

      val actualSenderIdx =
        groupInfo.groupContext
          .extension<ExternalSenders>()
          ?.externalSenders
          ?.indexOfFirst { (it.credential as BasicCredential).identity.contentEquals(signer.credential.identity) }
          ?.takeIf { it != -1 }
          ?: invalidArgument("External signer ${request.signerId} is not registered for the group")

      if (actualSenderIdx != request.signerIndex) {
        invalidArgument("Signer index doesn't match: request=${request.signerIndex}, actual=$actualSenderIdx")
      }

      externalProposalMessage(
        request.description.toProposal(groupInfo.cipherSuite, groupInfo.groupId, tree),
        groupInfo.groupContext,
        actualSenderIdx.toUInt(),
        signer.signatureKeyPair.private,
      ).bind().asProposalResponse()
    }

  override fun free(request: FreeRequest): Future<FreeResponse> =
    launchFuture<Nothing, _> {
      stateStore.removeState(request.stateId)
      FreeResponse.getDefaultInstance()
    }

  private inline fun <E, T> launchFuture(crossinline block: suspend Raise<E>.() -> T): Future<T> =
    Promise.promise<T>().apply {
      launch {
        try {
          either { this.block() }
            .onRight { complete(it) }
            .onLeft { fail(it.toString()) }
        } catch (t: Throwable) {
          fail(t)
        }
      }
    }.future()
}
