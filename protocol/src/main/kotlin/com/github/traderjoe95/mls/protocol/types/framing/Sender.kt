package com.github.traderjoe95.mls.protocol.types.framing

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType

data class Sender(val type: SenderType, val index: LeafIndex?) : Struct2T.Shape<SenderType, LeafIndex?> {
  companion object : Encodable<Sender> {
    override val dataT: DataType<Sender> =
      throwAnyError {
        struct("Sender") {
          it.field("sender_type", SenderType.T)
            .select<LeafIndex?, _>(SenderType.T, "sender_type") {
              case(SenderType.Member).then(LeafIndex.dataT, "leaf_index")
                .case(SenderType.External).then(LeafIndex.dataT, "sender_index")
                .orElseNothing()
            }
        }.lift(::Sender)
      }

    fun member(leafIndex: LeafIndex): Sender = Sender(SenderType.Member, leafIndex)

    fun external(senderIndex: LeafIndex): Sender = Sender(SenderType.External, senderIndex)

    fun newMemberProposal(): Sender = Sender(SenderType.NewMemberProposal, null)

    fun newMemberCommit(): Sender = Sender(SenderType.NewMemberCommit, null)
  }
}
