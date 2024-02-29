package com.github.traderjoe95.mls.protocol.types

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import java.security.SecureRandom

interface Movable<T : Movable<T>> {
  fun move(): T
}

interface Copyable<T : Copyable<T>> {
  fun copy(): T
}

interface Wipable {
  fun wipe()
}

interface MoveCopyWipe<T : MoveCopyWipe<T>> : Movable<T>, Copyable<T>, Wipable {
  override fun move(): T = copy().also { wipe() }
}

interface RefinedBytes<T : RefinedBytes<T>> {
  val bytes: ByteArray

  infix fun eq(other: T): Boolean = bytes.contentEquals(other.bytes)

  infix fun neq(other: T): Boolean = !(this eq other)

  val hashCode: Int
    get() = bytes.contentHashCode()

  companion object {
    inline fun <reified T : RefinedBytes<T>> dataT(
      crossinline constructor: (ByteArray) -> T,
      name: String? = null,
    ): DataType<T> = opaque[V].derive({ constructor(it) }, { it.bytes }, name)

    infix fun <T : RefinedBytes<T>> T?.eqNullable(other: T?): Boolean =
      when {
        this == null && other == null -> true
        this != null && other != null -> this eq other
        else -> false
      }

    infix fun <T : RefinedBytes<T>> T?.neqNullable(other: T?): Boolean = !(this eqNullable other)
  }
}

@JvmInline
value class GroupId(override val bytes: ByteArray) : RefinedBytes<GroupId> {
  companion object : Encodable<GroupId> {
    private val RANDOM = SecureRandom()

    override val dataT: DataType<GroupId> = RefinedBytes.dataT(::GroupId)

    val ByteArray.asGroupId: GroupId
      get() = GroupId(this)

    fun new(length: UInt = 32U): GroupId {
      require(length in 16U..128U) { "Group IDs outside of 16..128 bytes of length aren't supported" }

      return ByteArray(length.toInt()).also { RANDOM.nextBytes(it) }.asGroupId
    }
  }
}
