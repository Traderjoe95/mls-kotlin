package com.github.traderjoe95.mls.interop

import arrow.core.Either
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.interop.proto.CommitRequest
import com.github.traderjoe95.mls.interop.proto.Extension
import com.github.traderjoe95.mls.interop.proto.HandleCommitRequest
import com.github.traderjoe95.mls.interop.proto.PreSharedKey
import com.github.traderjoe95.mls.interop.proto.ProposalDescription
import com.github.traderjoe95.mls.interop.proto.ProposalResponse
import com.github.traderjoe95.mls.interop.proto.proposalResponse
import com.github.traderjoe95.mls.interop.store.StoredState
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.CreateSignatureError
import com.github.traderjoe95.mls.protocol.error.ProcessMessageError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.PrepareCommitResult
import com.github.traderjoe95.mls.protocol.group.prepareCommit
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.GroupMessage
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.ensureFormat
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.ensureFormatAndContent
import com.github.traderjoe95.mls.protocol.message.MlsProposalMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.ResolvedPsk
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTreeOps
import com.github.traderjoe95.mls.protocol.tree.findLeaf
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.Extension.Companion.decodeExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.GroupId.Companion.asGroupId
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import com.github.traderjoe95.mls.protocol.util.hex
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteString

fun RefinedBytes<*>.toByteString(): ByteString = bytes.toByteString()

fun newKeyPackage(
  cipherSuite: CipherSuite,
  credential: BasicCredential,
): Either<CreateSignatureError, KeyPackage.Private> =
  KeyPackage.generate(
    cipherSuite,
    cipherSuite.generateSignatureKeyPair(),
    credential,
    Capabilities.default(),
    Lifetime.always(),
  )

fun RatchetTreeOps.findMember(identity: ByteArray): LeafIndex =
  findLeaf { (credential as BasicCredential).identity.contentEquals(identity) }
    ?.second
    ?: invalidArgument("Member with identity ${identity.hex} not found")

fun MlsProposalMessage.asProposalResponse(): ProposalResponse =
  proposalResponse {
    proposal = encoded.toByteString()
  }

fun PreSharedKey.toResolvedPsk(cipherSuite: CipherSuite): ResolvedPsk =
  ResolvedPsk(
    ExternalPskId(pskId.toByteArray(), cipherSuite.generateNonce(cipherSuite.hashLen)),
    pskSecret.toByteArray().asSecret,
  )

context(Raise<DecoderError>)
fun Extension.toExtension(): GroupContextExtension<*> =
  decodeExtension(extensionType.toUShort(), extensionData.toByteArray()) as GroupContextExtension<*>

context(Raise<ProcessMessageError>)
fun ByteString.decodeKeyPackage(): KeyPackage =
  com.github.traderjoe95.mls.protocol.error.DecoderError.wrap {
    MlsMessage.decode(toByteArray()).ensureFormat<KeyPackage>().message
  }

context(Raise<ProcessMessageError>)
fun ByteString.decodeWelcome(): Welcome =
  com.github.traderjoe95.mls.protocol.error.DecoderError.wrap {
    MlsMessage.decode(toByteArray()).ensureFormat<Welcome>().message
  }

context(Raise<ProcessMessageError>)
fun ByteString.decodeGroupInfo(): GroupInfo =
  com.github.traderjoe95.mls.protocol.error.DecoderError.wrap {
    MlsMessage.decode(toByteArray()).ensureFormat<GroupInfo>().message
  }

context(Raise<ProcessMessageError>)
fun ByteString.decodeProposal(state: StoredState): GroupMessage<Proposal> =
  com.github.traderjoe95.mls.protocol.error.DecoderError.wrap {
    MlsMessage.decode(toByteArray())
      .ensureFormatAndContent(state.handshakeOptions.wireFormat, ContentType.Proposal)
      .message
  }

context(Raise<ProcessMessageError>)
fun ByteString.decodeCommit(state: StoredState): GroupMessage<Commit> =
  com.github.traderjoe95.mls.protocol.error.DecoderError.wrap {
    MlsMessage.decode(toByteArray())
      .ensureFormatAndContent(state.handshakeOptions.wireFormat, ContentType.Commit)
      .message
  }

context(Raise<Any>)
fun ProposalDescription.toProposal(
  cipherSuite: ICipherSuite,
  groupId: GroupId,
  tree: RatchetTreeOps,
): Proposal =
  when (val t = proposalType.toStringUtf8()) {
    "add" -> Add(keyPackage.decodeKeyPackage())

    "remove" -> Remove(tree.findMember(removedId.toByteArray()))

    "externalPSK" ->
      com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey(
        ExternalPskId.create(pskId.toByteArray(), cipherSuite),
      )

    "resumptionPSK" ->
      com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey(
        ResumptionPskId.application(groupId, epochId.toULong(), cipherSuite),
      )

    "groupContextExtensions" ->
      GroupContextExtensions(extensionsList.map { it.toExtension() })

    "reinit" ->
      ReInit(
        this@toProposal.groupId.toByteArray().asGroupId,
        ProtocolVersion.MLS_1_0,
        CipherSuite(this@toProposal.cipherSuite.toUShort())!!,
        extensionsList.map { it.toExtension() },
      )

    else -> error("Unsupported by-value proposal type $t")
  }

context(Raise<Any>)
suspend fun CommitRequest.createCommit(state: StoredState): PrepareCommitResult {
  val groupStateBeforeCommit =
    byReferenceList.fold(state.groupState) { groupState, proposalBytes ->
      groupState.ensureActive().process(
        proposalBytes.decodeProposal(state),
        AuthService,
        state,
      ).bind()
    }

  val proposalRefs =
    groupStateBeforeCommit.ensureActive()
      .getStoredProposals()
      .sortedBy { it.received }
      .map { it.ref }
  val inlineProposals =
    byValueList.map { it.toProposal(state.groupState.cipherSuite, state.groupState.groupId, state.groupState.tree) }

  return groupStateBeforeCommit.ensureActive().prepareCommit(
    proposalRefs + inlineProposals,
    AuthService,
    messageOptions = state.handshakeOptions,
    forcePath = forcePath,
    inlineTree = !externalTree,
  ).bind()
}

context(Raise<ProcessMessageError>)
suspend fun HandleCommitRequest.processCommit(state: StoredState): GroupState {
  val groupStateBeforeCommit =
    proposalList.fold(state.groupState) { groupState, proposalBytes ->
      groupState.ensureActive().process(
        proposalBytes.decodeProposal(state),
        AuthService,
        state,
      ).bind()
    }

  val commit = commit.decodeCommit(state)

  val newGroupState = groupStateBeforeCommit.ensureActive { process(commit, AuthService, state) }.bind()
  return newGroupState
}
