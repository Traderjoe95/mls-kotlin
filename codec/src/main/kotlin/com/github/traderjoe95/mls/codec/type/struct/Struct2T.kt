package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.SelectError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.struct.member.Field
import com.github.traderjoe95.mls.codec.type.struct.member.Member
import com.github.traderjoe95.mls.codec.type.struct.member.SelectBuilder
import com.github.traderjoe95.mls.codec.util.Slice

class Struct2T<A, B> private constructor(
  name: String,
  val member1: Field<A>,
  val member2: Member<B>,
) : StructT<Struct2<A, B>>(name, member1, member2) {
  context(Raise<EncoderError>)
  override fun encode(value: Struct2<A, B>): ByteArray =
    member1.encodeValue(value.field1, value, this) +
      member2.encodeValue(value.field2, value, this)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<Struct2<A, B>, Slice> =
    member1.decodeValue(bytes, null, this).let { (a, remainingA) ->
      member2.decodeValue(remainingA, Struct1(a), this).let { (b, remaining) ->
        Struct2(a, b) to remaining
      }
    }

  fun create(
    field1: A,
    field2: B,
  ): Struct2<A, B> = Struct2(field1, field2)

  class Builder<A, B>
    @PublishedApi
    internal constructor(
      @PublishedApi override val name: String,
      @PublishedApi internal val member1: Field<A>,
      @PublishedApi internal val member2: Member<B>,
    ) : StructBuilder<Struct2<A, B>, Struct2T<A, B>>() {
      override val nextIndex: UInt = 2U

      fun <C> field(
        fieldName: String,
        type: DataType<C>,
      ): Struct3T.Builder<A, B, C> = Struct3T.Builder(name, member1, member2, createField(fieldName, type))

      fun <C> field(
        fieldName: String,
        type: DataType<C>,
        constant: C,
      ): Struct3T.Builder<A, B, C> = Struct3T.Builder(name, member1, member2, createField(fieldName, type, constant.some()))

      context(Raise<SelectError>)
      inline fun <C, reified _E> select(
        enumT: EnumT<_E>,
        fieldName: String,
        vararg nestedPath: String,
        crossinline block: SelectBuilder<C, _E>.() -> SelectBuilder<C, _E>,
      ): Struct3T.Builder<A, B, C> where _E : ProtocolEnum<_E> =
        Struct3T.Builder(name, member1, member2, createSelect(enumT, fieldName, *nestedPath, block = block))

      @PublishedApi
      override fun buildStructT(): Struct2T<A, B> = Struct2T(name, member1, member2)
    }

  interface Shape<out A, out B> {
    operator fun component1(): A

    operator fun component2(): B
  }
}
