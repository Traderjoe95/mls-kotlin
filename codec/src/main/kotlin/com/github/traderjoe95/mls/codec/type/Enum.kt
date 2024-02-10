package com.github.traderjoe95.mls.codec.type

import arrow.core.raise.Raise
import arrow.core.toNonEmptyListOrNull
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.EnumError
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.byteLength
import com.github.traderjoe95.mls.codec.util.fromBytes
import com.github.traderjoe95.mls.codec.util.intersect
import com.github.traderjoe95.mls.codec.util.isNotEmpty
import com.github.traderjoe95.mls.codec.util.toBytes

context(Raise<EnumError>)
inline fun <reified E> enum(): EnumT<E> where E : Enum<E>, E : ProtocolEnum<E> = EnumT.create<E>()

context(Raise<EnumError>)
inline fun <reified E : ProtocolEnum<E>> enum(vararg values: E): EnumT<E> = EnumT.create(*values)

class EnumT<V>
  @PublishedApi
  internal constructor(
    override val name: String,
    @PublishedApi internal val values: Array<V>,
  ) : DataType<V> where V : ProtocolEnum<V> {
  private val byteWidth: UInt = values.maxOf { it.ord.last }.byteLength
  override val encodedLength: UInt
    get() = byteWidth

  context(Raise<EncoderError>)
  override fun encode(value: V): ByteArray =
    if (value.isValid) {
      value.ord.first.toBytes(byteWidth)
    } else {
      raise(EncoderError.InvalidEnumValue(name, value.name))
    }

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<V, Slice> =
    bytes.take(byteWidth) { b ->
      val ord = UInt.fromBytes(b)
      values.find { ord in it.ord } ?: raise(DecoderError.UnknownEnumValue(bytes.firstIndex, name, ord))
    }.apply {
      if (!first.isValid) raise(DecoderError.InvalidEnumValue(bytes.firstIndex, name, first.name))
    }

  override fun toString(): String = "enum {\n  ${values.joinToString(",\n  ") { "${it.enumName}(${it.ordStr})" }}\n} $name"

  companion object {
    context(Raise<EnumError>)
    inline fun <reified E> create(): EnumT<E> where E : Enum<E>, E : ProtocolEnum<E> = create(*enumValues<E>())

    context(Raise<EnumError>)
    inline fun <reified E : ProtocolEnum<E>> create(vararg values: E): EnumT<E> {
      val name = E::class.simpleName!!
      val sortedValues = values.sortedBy { it.ord.first }.toNonEmptyListOrNull() ?: raise(EnumError.NoValues(name))

      // Check overlaps in enum ord
      sortedValues.associateWith { other ->
        sortedValues.filter {
          it != other && it.ord.intersect(other.ord).isNotEmpty()
        }.map { it.name }.toSet()
      }.mapKeys {
        it.key.name
      }.filterValues(Set<String>::isNotEmpty).let {
        if (it.isNotEmpty()) raise(EnumError.AmbiguousOrd(name, it))
      }

      // Check for constants that have no valid ord
      sortedValues.filter { it.ord.isEmpty() }.map { it.name }.toSet().let {
        if (it.isNotEmpty()) raise(EnumError.UndefinedOrd(name, it))
      }

      return EnumT(name, sortedValues.toTypedArray())
    }
  }
}

interface ProtocolEnum<T : ProtocolEnum<T>> : Comparable<T> {
  val ord: UIntRange
  val isValid: Boolean
  val name: String

  val enumName: String
    get() = if (name.lowercase() == "upper_") "" else name
  val ordStr: String
    get() = if (ord.first == ord.last) "${ord.first}" else "$ord"
}
