package com.github.traderjoe95.mls.protocol.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.message.GroupInfo.Tbs.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTreeOps
import com.github.traderjoe95.mls.protocol.types.GroupInfoExtension
import com.github.traderjoe95.mls.protocol.types.GroupInfoExtensions
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.extensionList

data class GroupInfo(
  val groupContext: GroupContext,
  override val extensions: GroupInfoExtensions,
  val confirmationTag: Mac,
  val signer: LeafIndex,
  val signature: Signature,
) : HasExtensions<GroupInfoExtension<*>>(),
  Message,
  Struct5T.Shape<GroupContext, GroupInfoExtensions, Mac, LeafIndex, Signature> {
  context(ICipherSuite, Raise<SignatureError>)
  fun verifySignature(tree: RatchetTreeOps) {
    val verificationKey = tree.leafNode(signer).signaturePublicKey

    verifyWithLabel(
      verificationKey,
      "GroupInfoTBS",
      Tbs(groupContext, extensions, confirmationTag, signer).encodeUnsafe(),
      signature,
    )
  }

  companion object : Encodable<GroupInfo> {
    @Suppress("kotlin:S6531")
    override val dataT: DataType<GroupInfo> =
      struct("GroupInfo") {
        it.field("group_context", GroupContext.dataT)
          .field("extensions", GroupInfoExtension.dataT.extensionList())
          .field("confirmation_tag", Mac.dataT)
          .field("signer", LeafIndex.dataT)
          .field("signature", Signature.dataT)
      }.lift(::GroupInfo)

    fun create(
      groupContext: GroupContext,
      confirmationTag: Mac,
      extensions: List<GroupInfoExtension<*>> = listOf(),
      ownLeafIndex: LeafIndex,
      signaturePrivateKey: SignaturePrivateKey,
    ): GroupInfo =
      GroupInfo(
        groupContext,
        extensions,
        confirmationTag,
        ownLeafIndex,
        groupContext.cipherSuite.signWithLabel(
          signaturePrivateKey,
          "GroupInfoTBS",
          Tbs(groupContext, extensions, confirmationTag, ownLeafIndex).encodeUnsafe(),
        ),
      )
  }

  data class Tbs(
    val groupContext: GroupContext,
    val extensions: List<GroupInfoExtension<*>>,
    val confirmationTag: Mac,
    val signer: LeafIndex,
  ) : Struct4T.Shape<GroupContext, List<GroupInfoExtension<*>>, Mac, LeafIndex> {
    companion object : Encodable<Tbs> {
      @Suppress("kotlin:S6531")
      override val dataT: DataType<Tbs> =
        struct("GroupInfo") {
          it.field("group_context", GroupContext.dataT)
            .field("extensions", GroupInfoExtension.dataT.extensionList())
            .field("confirmation_tag", Mac.dataT)
            .field("signer", LeafIndex.dataT)
        }.lift(GroupInfo::Tbs)
    }
  }
}
