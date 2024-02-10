package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.Struct3
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

class Struct3T<A, B, C> private constructor(
  name: String,
  val member1: Field<A>,
  val member2: Member<B>,
  val member3: Member<C>,
) : StructT<Struct3<A, B, C>>(name, member1, member2, member3) {
  context(Raise<EncoderError>)
  override fun encode(value: Struct3<A, B, C>): ByteArray =
    member1.encodeValue(value.field1, value, this) +
      member2.encodeValue(value.field2, value, this) +
      member3.encodeValue(value.field3, value, this)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<Struct3<A, B, C>, Slice> =
    member1.decodeValue(bytes, null, this).let { (a, remainingA) ->
      member2.decodeValue(remainingA, Struct1(a), this).let { (b, remainingB) ->
        member3.decodeValue(remainingB, Struct2(a, b), this).let { (c, remaining) ->
          Struct3(a, b, c) to remaining
        }
      }
    }

  fun create(
    field1: A,
    field2: B,
    field3: C,
  ): Struct3<A, B, C> = Struct3(field1, field2, field3)

  class Builder<A, B, C>
    @PublishedApi
    internal constructor(
      @PublishedApi override val name: String,
      @PublishedApi internal val member1: Field<A>,
      @PublishedApi internal val member2: Member<B>,
      @PublishedApi internal val member3: Member<C>,
    ) : StructBuilder<Struct3<A, B, C>, Struct3T<A, B, C>>() {
      override val nextIndex: UInt = 3U

      fun <D> field(
        fieldName: String,
        type: DataType<D>,
      ): Struct4T.Builder<A, B, C, D> = Struct4T.Builder(name, member1, member2, member3, createField(fieldName, type))

      fun <D> field(
        fieldName: String,
        type: DataType<D>,
        constant: D,
      ): Struct4T.Builder<A, B, C, D> = Struct4T.Builder(name, member1, member2, member3, createField(fieldName, type, constant.some()))

      context(Raise<SelectError>)
      inline fun <D, reified _E> select(
        enumT: EnumT<_E>,
        fieldName: String,
        vararg nestedPath: String,
        crossinline block: SelectBuilder<D, _E>.() -> SelectBuilder<D, _E>,
      ): Struct4T.Builder<A, B, C, D> where _E : ProtocolEnum<_E> =
        Struct4T.Builder(name, member1, member2, member3, createSelect(enumT, fieldName, *nestedPath, block = block))

      @PublishedApi
      override fun buildStructT(): Struct3T<A, B, C> = Struct3T(name, member1, member2, member3)
    }

  interface Shape<out A, out B, out C> {
    operator fun component1(): A

    operator fun component2(): B

    operator fun component3(): C
  }
}
