package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.Struct7T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint64
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.util.hex

data class GroupContext(
  val protocolVersion: ProtocolVersion,
  val cipherSuite: CipherSuite,
  val groupId: GroupId,
  val epoch: ULong,
  val treeHash: ByteArray,
  val confirmedTranscriptHash: ByteArray,
  override val extensions: GroupContextExtensions = listOf(),
  val interimTranscriptHash: ByteArray = byteArrayOf(),
) : HasExtensions<GroupContextExtension<*>>(),
  Struct7T.Shape<ProtocolVersion, CipherSuite, GroupId, ULong, ByteArray, ByteArray, GroupContextExtensions> {
  inline val encoded: ByteArray
    get() = encodeUnsafe()

  internal fun provisional(tree: RatchetTree): GroupContext =
    GroupContext(
      protocolVersion,
      cipherSuite,
      groupId,
      epoch + 1U,
      tree.treeHash(cipherSuite),
      confirmedTranscriptHash,
      extensions,
      interimTranscriptHash,
    )

  fun withExtensions(extensions: List<GroupContextExtension<*>>?): GroupContext =
    GroupContext(
      protocolVersion,
      cipherSuite,
      groupId,
      epoch,
      treeHash,
      confirmedTranscriptHash,
      extensions ?: this.extensions,
      interimTranscriptHash,
    )

  fun withInterimTranscriptHash(interimTranscriptHash: ByteArray): GroupContext =
    GroupContext(
      protocolVersion,
      cipherSuite,
      groupId,
      epoch,
      treeHash,
      confirmedTranscriptHash,
      extensions,
      interimTranscriptHash,
    )

  fun toShortString(): String = "GroupContext[v=$protocolVersion, id=${groupId.hex}, epoch=$epoch]"

  companion object : Encodable<GroupContext> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<GroupContext> =
      struct("GroupContext") {
        it.field("version", ProtocolVersion.T, ProtocolVersion.MLS_1_0)
          .field("cipher_suite", CipherSuite.T)
          .field("group_id", GroupId.T)
          .field("epoch", uint64.asULong)
          .field("tree_hash", opaque[V])
          .field("confirmed_transcript_hash", opaque[V])
          .field("extensions", GroupContextExtension.T.extensionList())
      }.lift(::GroupContext)

    context(Raise<GroupCreationError>)
    fun new(
      protocolVersion: ProtocolVersion,
      cipherSuite: CipherSuite,
      tree: RatchetTree,
      vararg extensions: GroupContextExtension<*>,
      groupId: GroupId? = null,
    ): GroupContext =
      GroupContext(
        protocolVersion,
        cipherSuite,
        groupId ?: GroupId.new(),
        0UL,
        tree.treeHash(cipherSuite),
        byteArrayOf(),
        extensions.toList(),
      )
  }

  data class ConfirmedTranscriptHashInput(
    val wireFormat: WireFormat,
    val framedContent: FramedContent<*>,
    val signature: Signature,
  ) : Struct3T.Shape<WireFormat, FramedContent<*>, Signature> {
    companion object : Encodable<ConfirmedTranscriptHashInput> {
      @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
      override val T: DataType<ConfirmedTranscriptHashInput> =
        struct("ConfirmedTranscriptHashInput") {
          it.field("wire_format", WireFormat.T)
            .field("content", FramedContent.T)
            .field("signature", Signature.T)
        }.lift(::ConfirmedTranscriptHashInput)
    }
  }

  data class InterimTranscriptHashInput(
    val confirmationTag: Mac,
  ) : Struct1T.Shape<Mac> {
    companion object : Encodable<InterimTranscriptHashInput> {
      @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
      override val T: DataType<InterimTranscriptHashInput> =
        struct("InterimTranscriptHashInput") {
          it.field("confirmation_tag", Mac.T)
        }.lift(::InterimTranscriptHashInput)
    }
  }
}
