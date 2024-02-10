package com.github.traderjoe95.mls.protocol.types.framing.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.types.GroupInfoExtension
import com.github.traderjoe95.mls.protocol.types.GroupInfoExtensions
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

data class GroupInfo(
  val groupContext: GroupContext,
  override val extensions: GroupInfoExtensions,
  val confirmationTag: Mac,
  val signer: UInt,
  val signature: Signature,
) : HasExtensions<GroupInfoExtension<*>>(),
  Message,
  Struct5T.Shape<GroupContext, GroupInfoExtensions, Mac, UInt, Signature> {
  context(ICipherSuite, Raise<SignatureError>)
  fun verifySignature(tree: RatchetTree) {
    val verificationKey = tree.leaves[signer]!!.node.verificationKey

    verifyWithLabel(
      verificationKey,
      "GroupInfoTBS",
      EncoderError.wrap { Tbs.T.encode(Tbs(groupContext, extensions, confirmationTag, signer)) },
      signature,
    )
  }

  companion object {
    @Suppress("kotlin:S6531")
    val T: DataType<GroupInfo> =
      struct("GroupInfo") {
        it.field("group_context", GroupContext.T)
          .field("extensions", GroupInfoExtension.T.extensionList())
          .field("confirmation_tag", Mac.T)
          .field("signer", uint32.asUInt)
          .field("signature", Signature.T)
      }.lift(::GroupInfo)

    context(GroupState, Raise<BaseEncoderError>)
    fun create(
      groupContext: GroupContext,
      extensions: List<GroupInfoExtension<*>>,
      confirmationTag: Mac,
    ): GroupInfo =
      GroupInfo(
        groupContext,
        extensions,
        confirmationTag,
        ownLeafIndex,
        signWithLabel(
          signingKey,
          "GroupInfoTBS",
          Tbs.T.encode(Tbs(groupContext, extensions, confirmationTag, ownLeafIndex)),
        ),
      )
  }

  data class Tbs(
    val groupContext: GroupContext,
    val extensions: List<GroupInfoExtension<*>>,
    val confirmationTag: Mac,
    val signer: UInt,
  ) : Struct4T.Shape<GroupContext, List<GroupInfoExtension<*>>, Mac, UInt> {
    companion object {
      @Suppress("kotlin:S6531")
      val T: DataType<Tbs> =
        struct("GroupInfo") {
          it.field("group_context", GroupContext.T)
            .field("extensions", GroupInfoExtension.T.extensionList())
            .field("confirmation_tag", Mac.T)
            .field("signer", uint32.asUInt)
        }.lift(::Tbs)
    }
  }
}
