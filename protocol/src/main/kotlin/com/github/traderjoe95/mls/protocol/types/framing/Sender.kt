package com.github.traderjoe95.mls.protocol.types.framing

import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType

data class Sender(val type: SenderType, val index: UInt?) : Struct2T.Shape<SenderType, UInt?> {
  companion object {
    val T: DataType<Sender> =
      throwAnyError {
        struct("Sender") {
          it.field("sender_type", SenderType.T)
            .select<UInt?, _>(SenderType.T, "sender_type") {
              case(SenderType.Member).then(uint32.asUInt, "leaf_index")
                .case(SenderType.External).then(uint32.asUInt, "sender_index")
                .orElseNothing()
            }
        }.lift(::Sender)
      }

    fun member(leafIndex: UInt): Sender = Sender(SenderType.Member, leafIndex)

    fun external(senderIndex: UInt): Sender = Sender(SenderType.External, senderIndex)

    fun newMemberProposal(): Sender = Sender(SenderType.NewMemberProposal, null)

    fun newMemberCommit(): Sender = Sender(SenderType.NewMemberCommit, null)
  }
}
