package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.Struct3
import com.github.traderjoe95.mls.codec.Struct4
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

class Struct4T<A, B, C, D> private constructor(
  name: String,
  val member1: Field<A>,
  val member2: Member<B>,
  val member3: Member<C>,
  val member4: Member<D>,
) : StructT<Struct4<A, B, C, D>>(name, member1, member2, member3, member4) {
  context(Raise<EncoderError>)
  override fun encode(value: Struct4<A, B, C, D>): ByteArray =
    member1.encodeValue(value.field1, value, this) +
      member2.encodeValue(value.field2, value, this) +
      member3.encodeValue(value.field3, value, this) +
      member4.encodeValue(value.field4, value, this)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<Struct4<A, B, C, D>, Slice> =
    member1.decodeValue(bytes, null, this).let { (a, remainingA) ->
      member2.decodeValue(remainingA, Struct1(a), this).let { (b, remainingB) ->
        member3.decodeValue(remainingB, Struct2(a, b), this).let { (c, remainingC) ->
          member4.decodeValue(remainingC, Struct3(a, b, c), this).let { (d, remaining) ->
            Struct4(a, b, c, d) to remaining
          }
        }
      }
    }

  fun create(
    field1: A,
    field2: B,
    field3: C,
    field4: D,
  ): Struct4<A, B, C, D> = Struct4(field1, field2, field3, field4)

  class Builder<A, B, C, D>
    @PublishedApi
    internal constructor(
      @PublishedApi override val name: String,
      @PublishedApi internal val member1: Field<A>,
      @PublishedApi internal val member2: Member<B>,
      @PublishedApi internal val member3: Member<C>,
      @PublishedApi internal val member4: Member<D>,
    ) : StructBuilder<Struct4<A, B, C, D>, Struct4T<A, B, C, D>>() {
      override val nextIndex: UInt = 4U

      fun <E> field(
        fieldName: String,
        type: DataType<E>,
      ): Struct5T.Builder<A, B, C, D, E> = Struct5T.Builder(name, member1, member2, member3, member4, createField(fieldName, type))

      fun <E> field(
        fieldName: String,
        type: DataType<E>,
        constant: E,
      ): Struct5T.Builder<A, B, C, D, E> =
        Struct5T.Builder(name, member1, member2, member3, member4, createField(fieldName, type, constant.some()))

      context(Raise<SelectError>)
      inline fun <E, reified _E> select(
        enumT: EnumT<_E>,
        fieldName: String,
        vararg nestedPath: String,
        crossinline block: SelectBuilder<E, _E>.() -> SelectBuilder<E, _E>,
      ): Struct5T.Builder<A, B, C, D, E> where _E : ProtocolEnum<_E> =
        Struct5T.Builder(
          name,
          member1,
          member2,
          member3,
          member4,
          createSelect(enumT, fieldName, *nestedPath, block = block),
        )

      @PublishedApi
      override fun buildStructT(): Struct4T<A, B, C, D> = Struct4T(name, member1, member2, member3, member4)
    }

  interface Shape<out A, out B, out C, out D> {
    operator fun component1(): A

    operator fun component2(): B

    operator fun component3(): C

    operator fun component4(): D
  }
}
