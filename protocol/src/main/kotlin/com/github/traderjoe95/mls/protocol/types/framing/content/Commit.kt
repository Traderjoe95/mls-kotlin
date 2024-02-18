package com.github.traderjoe95.mls.protocol.types.framing.content

import arrow.core.None
import arrow.core.Option
import arrow.core.some
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath

data class Commit(
  val proposals: List<ProposalOrRef>,
  val updatePath: Option<UpdatePath>,
) : Content, Struct2T.Shape<List<ProposalOrRef>, Option<UpdatePath>> {
  constructor(proposals: List<ProposalOrRef>, updatePath: UpdatePath) : this(proposals, updatePath.some())
  constructor(proposals: List<ProposalOrRef>) : this(proposals, None)

  override val contentType: ContentType = ContentType.Commit

  companion object : Encodable<Commit> {
    override val dataT: DataType<Commit> =
      struct("Commit") {
        it.field("proposals", ProposalOrRef.dataT[V])
          .field("update_path", optional[UpdatePath.dataT])
      }.lift(::Commit)

    val empty: Commit
      get() = Commit(listOf(), None)
  }
}

sealed interface ProposalOrRef {
  val proposalOrRef: ProposalOrRefType

  companion object : Encodable<ProposalOrRef> {
    override val dataT: DataType<ProposalOrRef> =
      struct("ProposalOrRef") {
        it.field("type", ProposalOrRefType.T)
          .select<ProposalOrRef, _>(ProposalOrRefType.T, "type") {
            case(ProposalOrRefType.Proposal).then(Proposal.dataT)
              .case(ProposalOrRefType.Reference).then(Proposal.Ref.T)
          }
      }.lift({ _, p -> p }, { Struct2(it.proposalOrRef, it) })
  }
}

enum class ProposalOrRefType(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<ProposalOrRefType> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0U, false),

  Proposal(1U),
  Reference(2U),
  ;

  override val ord: UIntRange = ord..ord

  companion object {
    val T: EnumT<ProposalOrRefType> = throwAnyError { enum(upperBound = 0xFFU) }
  }
}
