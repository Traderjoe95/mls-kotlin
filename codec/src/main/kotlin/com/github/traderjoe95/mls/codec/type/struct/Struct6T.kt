package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.Struct3
import com.github.traderjoe95.mls.codec.Struct4
import com.github.traderjoe95.mls.codec.Struct5
import com.github.traderjoe95.mls.codec.Struct6
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
import kotlin.experimental.ExperimentalTypeInference

class Struct6T<A, B, C, D, E, F> private constructor(
  name: String,
  val member1: Field<A>,
  val member2: Member<B>,
  val member3: Member<C>,
  val member4: Member<D>,
  val member5: Member<E>,
  val member6: Member<F>,
) : StructT<Struct6<A, B, C, D, E, F>>(name, member1, member2, member3, member4, member5, member6) {
  context(Raise<EncoderError>)
  override fun encode(value: Struct6<A, B, C, D, E, F>): ByteArray =
    member1.encodeValue(value.field1, value, this) +
      member2.encodeValue(value.field2, value, this) +
      member3.encodeValue(value.field3, value, this) +
      member4.encodeValue(value.field4, value, this) +
      member5.encodeValue(value.field5, value, this) +
      member6.encodeValue(value.field6, value, this)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<Struct6<A, B, C, D, E, F>, Slice> =
    member1.decodeValue(bytes, null, this).let { (a, remainingA) ->
      member2.decodeValue(remainingA, Struct1(a), this).let { (b, remainingB) ->
        member3.decodeValue(remainingB, Struct2(a, b), this).let { (c, remainingC) ->
          member4.decodeValue(remainingC, Struct3(a, b, c), this).let { (d, remainingD) ->
            member5.decodeValue(remainingD, Struct4(a, b, c, d), this).let { (e, remainingE) ->
              member6.decodeValue(remainingE, Struct5(a, b, c, d, e), this).let { (f, remaining) ->
                Struct6(a, b, c, d, e, f) to remaining
              }
            }
          }
        }
      }
    }

  fun create(
    field1: A,
    field2: B,
    field3: C,
    field4: D,
    field5: E,
    field6: F,
  ): Struct6<A, B, C, D, E, F> = Struct6(field1, field2, field3, field4, field5, field6)

  @OptIn(ExperimentalTypeInference::class)
  class Builder<A, B, C, D, E, F>
    @PublishedApi
    internal constructor(
      @PublishedApi override val name: String,
      @PublishedApi internal val member1: Field<A>,
      @PublishedApi internal val member2: Member<B>,
      @PublishedApi internal val member3: Member<C>,
      @PublishedApi internal val member4: Member<D>,
      @PublishedApi internal val member5: Member<E>,
      @PublishedApi internal val member6: Member<F>,
    ) : StructBuilder<Struct6<A, B, C, D, E, F>, Struct6T<A, B, C, D, E, F>>() {
      override val nextIndex: UInt = 6U

      fun <G> field(
        fieldName: String,
        type: DataType<G>,
      ): Struct7T.Builder<A, B, C, D, E, F, G> =
        Struct7T.Builder(name, member1, member2, member3, member4, member5, member6, createField(fieldName, type))

      fun <G> field(
        fieldName: String,
        type: DataType<G>,
        constant: G,
      ): Struct7T.Builder<A, B, C, D, E, F, G> =
        Struct7T.Builder(
          name,
          member1,
          member2,
          member3,
          member4,
          member5,
          member6,
          createField(fieldName, type, constant.some()),
        )

      context(Raise<SelectError>)
      inline fun <G, reified _E> select(
        enumT: EnumT<_E>,
        fieldName: String,
        vararg nestedPath: String,
        crossinline block: SelectBuilder<G, _E>.() -> SelectBuilder<G, _E>,
      ): Struct7T.Builder<A, B, C, D, E, F, G> where _E : ProtocolEnum<_E> =
        Struct7T.Builder(
          name,
          member1,
          member2,
          member3,
          member4,
          member5,
          member6,
          createSelect(enumT, fieldName, *nestedPath, block = block),
        )

      @PublishedApi override fun buildStructT(): Struct6T<A, B, C, D, E, F> =
        Struct6T(
          name,
          member1,
          member2,
          member3,
          member4,
          member5,
          member6,
        )
    }

  interface Shape<out A, out B, out C, out D, out E, out F> {
    operator fun component1(): A

    operator fun component2(): B

    operator fun component3(): C

    operator fun component4(): D

    operator fun component5(): E

    operator fun component6(): F
  }
}
