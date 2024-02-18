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
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.group.GroupContext.InterimTranscriptHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.T
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.suspending.new

class GroupContext(
  val protocolVersion: ProtocolVersion,
  val cipherSuite: CipherSuite,
  val groupId: ULID,
  val epoch: ULong,
  val treeHash: ByteArray,
  val confirmedTranscriptHash: ByteArray,
  override val extensions: GroupContextExtensions,
  val interimTranscriptHash: ByteArray = byteArrayOf(),
) : HasExtensions<GroupContextExtension<*>>(),
  Struct7T.Shape<ProtocolVersion, CipherSuite, ULID, ULong, ByteArray, ByteArray, GroupContextExtensions> {
  inline val encoded: ByteArray
    get() = encodeUnsafe()

  fun settings(keepPastEpochs: UInt = 5U): GroupSettings = GroupSettings(protocolVersion, cipherSuite, groupId, keepPastEpochs)

  override fun component1(): ProtocolVersion = protocolVersion

  override fun component2(): CipherSuite = cipherSuite

  override fun component3(): ULID = groupId

  override fun component4(): ULong = epoch

  override fun component5(): ByteArray = treeHash

  override fun component6(): ByteArray = confirmedTranscriptHash

  override fun component7(): List<GroupContextExtension<*>> = extensions

  context(ICipherSuite)
  internal fun provisional(tree: RatchetTree): GroupContext =
    GroupContext(
      protocolVersion,
      cipherSuite,
      groupId,
      epoch + 1U,
      tree.treeHash,
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

  context(ICipherSuite)
  fun withInterimTranscriptHash(confirmationTag: Mac): GroupContext =
    GroupContext(
      protocolVersion,
      cipherSuite,
      groupId,
      epoch,
      treeHash,
      confirmedTranscriptHash,
      extensions,
      hash(confirmedTranscriptHash + InterimTranscriptHashInput(confirmationTag).encodeUnsafe()),
    )

  companion object : Encodable<GroupContext> {
    @Suppress("kotlin:S6531")
    override val dataT: DataType<GroupContext> =
      struct("GroupContext") {
        it.field("version", ProtocolVersion.T, ProtocolVersion.MLS_1_0)
          .field("cipher_suite", CipherSuite.T)
          .field("group_id", ULID.T)
          .field("epoch", uint64.asULong)
          .field("tree_hash", opaque[V])
          .field("confirmed_transcript_hash", opaque[V])
          .field("extensions", GroupContextExtension.dataT.extensionList())
      }.lift(::GroupContext)

    context(Raise<GroupCreationError>)
    suspend fun new(
      cipherSuite: CipherSuite,
      keySchedule: KeySchedule,
      tree: RatchetTree,
      vararg extensions: GroupContextExtension<*>,
    ): GroupContext =
      GroupContext(
        ProtocolVersion.MLS_1_0,
        cipherSuite,
        ULID.new(),
        0UL,
        with(cipherSuite) { tree.treeHash },
        byteArrayOf(),
        extensions.toList(),
        cipherSuite.hash(
          InterimTranscriptHashInput(
            cipherSuite.mac(keySchedule.confirmationKey, byteArrayOf()),
          ).encodeUnsafe(),
        ),
      )

    internal fun create(
      settings: GroupSettings,
      epoch: GroupEpoch,
    ): GroupContext =
      GroupContext(
        settings.protocolVersion,
        settings.cipherSuite,
        settings.groupId,
        epoch.epoch,
        with(settings.cipherSuite) { epoch.tree.treeHash },
        epoch.confirmedTranscriptHash,
        epoch.extensions,
        epoch.interimTranscriptHash,
      )
  }

  data class ConfirmedTranscriptHashInput(
    val wireFormat: WireFormat,
    val framedContent: FramedContent<*>,
    val signature: Signature,
  ) : Struct3T.Shape<WireFormat, FramedContent<*>, Signature> {
    companion object : Encodable<ConfirmedTranscriptHashInput> {
      override val dataT: DataType<ConfirmedTranscriptHashInput> =
        struct("ConfirmedTranscriptHashInput") {
          it.field("wire_format", WireFormat.T)
            .field("content", FramedContent.dataT)
            .field("signature", Signature.dataT)
        }.lift(::ConfirmedTranscriptHashInput)
    }
  }

  data class InterimTranscriptHashInput(
    val confirmationTag: Mac,
  ) : Struct1T.Shape<Mac> {
    companion object : Encodable<InterimTranscriptHashInput> {
      override val dataT: DataType<InterimTranscriptHashInput> =
        struct("InterimTranscriptHashInput") {
          it.field("confirmation_tag", Mac.dataT)
        }.lift(::InterimTranscriptHashInput)
    }
  }
}
