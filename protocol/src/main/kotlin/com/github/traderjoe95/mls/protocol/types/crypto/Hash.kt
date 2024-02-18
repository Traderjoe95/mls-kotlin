package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage

@JvmInline
value class HashReference(val ref: ByteArray) {
  val asRef: KeyPackage.Ref
    get() = KeyPackage.Ref(ref)
  val asProposalRef: Proposal.Ref
    get() = Proposal.Ref(ref)

  internal val hashCode: Int
    get() = ref.contentHashCode()

  companion object : Encodable<HashReference> {
    override val dataT: DataType<HashReference> = opaque[V].derive({ HashReference(it) }, { it.ref }, name = "HashReference")

    val ByteArray.asHashReference: HashReference
      get() = HashReference(this)
  }
}

internal data class RefHashInput(val label: String, val value: ByteArray) : Struct2T.Shape<String, ByteArray> {
  companion object : Encodable<RefHashInput> {
    override val dataT = bytesAndLabel("RefHashInput", "value").lift(::RefHashInput)

    fun keyPackage(value: ByteArray): RefHashInput = RefHashInput("MLS 1.0 KeyPackage Reference", value)

    fun proposal(value: ByteArray): RefHashInput = RefHashInput("MLS 1.0 Proposal Reference", value)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as SignContent

    if (label != other.label) return false
    if (!value.contentEquals(other.content)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = label.hashCode()
    result = 31 * result + value.contentHashCode()
    return result
  }
}
