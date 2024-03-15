package com.github.traderjoe95.mls.protocol.message

import arrow.core.Either
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.GroupInfoError
import com.github.traderjoe95.mls.protocol.error.VerifySignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.message.GroupInfo.Tbs.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTreeOps
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.GroupInfoExtension
import com.github.traderjoe95.mls.protocol.types.GroupInfoExtensions
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class GroupInfo(
  val groupContext: GroupContext,
  override val extensions: GroupInfoExtensions,
  val confirmationTag: Mac,
  val signer: LeafIndex,
  val signature: Signature,
) : HasExtensions<GroupInfoExtension<*>>(),
  Message,
  Struct5T.Shape<GroupContext, GroupInfoExtensions, Mac, LeafIndex, Signature> {
  override val wireFormat: WireFormat = WireFormat.MlsGroupInfo

  val groupId: GroupId
    get() = groupContext.groupId
  val cipherSuite: CipherSuite
    get() = groupContext.cipherSuite

  override val encoded: ByteArray by lazy { encodeUnsafe() }

  fun verifySignature(tree: RatchetTreeOps): Either<VerifySignatureError, GroupInfo> =
    either {
      this@GroupInfo.apply {
        val verificationKey = tree.leafNode(signer).signaturePublicKey

        groupContext.cipherSuite.verifyWithLabel(
          verificationKey,
          "GroupInfoTBS",
          Tbs(groupContext, extensions, confirmationTag, signer).encodeUnsafe(),
          signature,
        )
      }
    }

  companion object : Encodable<GroupInfo> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<GroupInfo> =
      struct("GroupInfo") {
        it.field("group_context", GroupContext.T)
          .field("extensions", GroupInfoExtension.T.extensionList())
          .field("confirmation_tag", Mac.T)
          .field("signer", LeafIndex.T)
          .field("signature", Signature.T)
      }.lift(::GroupInfo)

    fun create(
      groupContext: GroupContext,
      confirmationTag: Mac,
      extensions: List<GroupInfoExtension<*>> = listOf(),
      ownLeafIndex: LeafIndex,
      signaturePrivateKey: SignaturePrivateKey,
    ): Either<GroupInfoError, GroupInfo> =
      either {
        GroupInfo(
          groupContext,
          extensions,
          confirmationTag,
          ownLeafIndex,
          groupContext.cipherSuite.signWithLabel(
            signaturePrivateKey,
            "GroupInfoTBS",
            Tbs(groupContext, extensions, confirmationTag, ownLeafIndex).encodeUnsafe(),
          ).bind(),
        )
      }
  }

  data class Tbs(
    val groupContext: GroupContext,
    val extensions: List<GroupInfoExtension<*>>,
    val confirmationTag: Mac,
    val signer: LeafIndex,
  ) : Struct4T.Shape<GroupContext, List<GroupInfoExtension<*>>, Mac, LeafIndex> {
    companion object : Encodable<Tbs> {
      @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
      override val T: DataType<Tbs> =
        struct("GroupInfo") {
          it.field("group_context", GroupContext.T)
            .field("extensions", GroupInfoExtension.T.extensionList())
            .field("confirmation_tag", Mac.T)
            .field("signer", LeafIndex.T)
        }.lift(GroupInfo::Tbs)
    }
  }
}
