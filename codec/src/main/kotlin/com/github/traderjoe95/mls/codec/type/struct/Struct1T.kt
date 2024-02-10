package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.SelectError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.struct.member.Field
import com.github.traderjoe95.mls.codec.type.struct.member.SelectBuilder
import com.github.traderjoe95.mls.codec.util.Slice

class Struct1T<A> private constructor(
  name: String,
  val member1: Field<A>,
) : StructT<Struct1<A>>(name, member1) {
  context(Raise<EncoderError>)
  override fun encode(value: Struct1<A>): ByteArray = member1.encodeValue(value.field1, value, this)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<Struct1<A>, Slice> =
    member1.decodeValue(bytes, null, this).let { (a, remaining) -> Struct1(a) to remaining }

  fun create(field1: A): Struct1<A> = Struct1(field1)

  class Builder<A> internal constructor(
    @PublishedApi override val name: String,
    @PublishedApi internal val member1: Field<A>,
  ) : StructBuilder<Struct1<A>, Struct1T<A>>() {
    override val nextIndex: UInt = 1U

    fun <B> field(
      fieldName: String,
      type: DataType<B>,
    ): Struct2T.Builder<A, B> = Struct2T.Builder(name, member1, createField(fieldName, type))

    fun <B> field(
      fieldName: String,
      type: DataType<B>,
      constant: B,
    ): Struct2T.Builder<A, B> = Struct2T.Builder(name, member1, createField(fieldName, type, constant.some()))

    context(Raise<SelectError>)
    inline fun <B, reified _E> select(
      enumT: EnumT<_E>,
      fieldName: String,
      vararg nestedPath: String,
      crossinline block: SelectBuilder<B, _E>.() -> SelectBuilder<B, _E>,
    ): Struct2T.Builder<A, B> where _E : ProtocolEnum<_E> =
      Struct2T.Builder(name, member1, createSelect(enumT, fieldName, *nestedPath, block = block))

    @PublishedApi
    override fun buildStructT(): Struct1T<A> = Struct1T(name, member1)
  }

  @Suppress("kotlin:S6517")
  interface Shape<out A> {
    operator fun component1(): A
  }
}
