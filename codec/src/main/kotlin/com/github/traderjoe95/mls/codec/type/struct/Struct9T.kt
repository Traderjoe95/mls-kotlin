package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.Struct3
import com.github.traderjoe95.mls.codec.Struct4
import com.github.traderjoe95.mls.codec.Struct5
import com.github.traderjoe95.mls.codec.Struct6
import com.github.traderjoe95.mls.codec.Struct7
import com.github.traderjoe95.mls.codec.Struct8
import com.github.traderjoe95.mls.codec.Struct9
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.struct.member.Field
import com.github.traderjoe95.mls.codec.type.struct.member.Member
import com.github.traderjoe95.mls.codec.util.Slice

class Struct9T<A, B, C, D, E, F, G, H, I> private constructor(
  name: String,
  val member1: Field<A>,
  val member2: Member<B>,
  val member3: Member<C>,
  val member4: Member<D>,
  val member5: Member<E>,
  val member6: Member<F>,
  val member7: Member<G>,
  val member8: Member<H>,
  val member9: Member<I>,
) : StructT<Struct9<A, B, C, D, E, F, G, H, I>>(
    name,
    member1,
    member2,
    member3,
    member4,
    member5,
    member6,
    member7,
    member8,
    member9,
  ) {
  context(Raise<EncoderError>)
  override fun encode(value: Struct9<A, B, C, D, E, F, G, H, I>): ByteArray =
    member1.encodeValue(value.field1, value, this) +
      member2.encodeValue(value.field2, value, this) +
      member3.encodeValue(value.field3, value, this) +
      member4.encodeValue(value.field4, value, this) +
      member5.encodeValue(value.field5, value, this) +
      member6.encodeValue(value.field6, value, this) +
      member7.encodeValue(value.field7, value, this) +
      member8.encodeValue(value.field8, value, this) +
      member9.encodeValue(value.field9, value, this)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<Struct9<A, B, C, D, E, F, G, H, I>, Slice> =
    member1.decodeValue(bytes, null, this).let { (a, remainingA) ->
      member2.decodeValue(remainingA, Struct1(a), this).let { (b, remainingB) ->
        member3.decodeValue(remainingB, Struct2(a, b), this).let { (c, remainingC) ->
          member4.decodeValue(remainingC, Struct3(a, b, c), this).let { (d, remainingD) ->
            member5.decodeValue(remainingD, Struct4(a, b, c, d), this).let { (e, remainingE) ->
              member6.decodeValue(remainingE, Struct5(a, b, c, d, e), this).let { (f, remainingF) ->
                member7.decodeValue(remainingF, Struct6(a, b, c, d, e, f), this).let { (g, remainingG) ->
                  member8.decodeValue(remainingG, Struct7(a, b, c, d, e, f, g), this).let { (h, remainingH) ->
                    member9.decodeValue(remainingH, Struct8(a, b, c, d, e, f, g, h), this).let { (i, remaining) ->
                      Struct9(a, b, c, d, e, f, g, h, i) to remaining
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

  @Suppress("kotlin:S107")
  fun create(
    field1: A,
    field2: B,
    field3: C,
    field4: D,
    field5: E,
    field6: F,
    field7: G,
    field8: H,
    field9: I,
  ): Struct9<A, B, C, D, E, F, G, H, I> = Struct9(field1, field2, field3, field4, field5, field6, field7, field8, field9)

  class Builder<A, B, C, D, E, F, G, H, I>
    @PublishedApi
    internal constructor(
      @PublishedApi override val name: String,
      @PublishedApi internal val member1: Field<A>,
      @PublishedApi internal val member2: Member<B>,
      @PublishedApi internal val member3: Member<C>,
      @PublishedApi internal val member4: Member<D>,
      @PublishedApi internal val member5: Member<E>,
      @PublishedApi internal val member6: Member<F>,
      @PublishedApi internal val member7: Member<G>,
      @PublishedApi internal val member8: Member<H>,
      @PublishedApi internal val member9: Member<I>,
    ) : StructBuilder<Struct9<A, B, C, D, E, F, G, H, I>, Struct9T<A, B, C, D, E, F, G, H, I>>() {
      override val nextIndex: UInt = 8U

      @PublishedApi
      override fun buildStructT(): Struct9T<A, B, C, D, E, F, G, H, I> =
        Struct9T(name, member1, member2, member3, member4, member5, member6, member7, member8, member9)
    }

  interface Shape<out A, out B, out C, out D, out E, out F, out G, out H, out I> {
    operator fun component1(): A

    operator fun component2(): B

    operator fun component3(): C

    operator fun component4(): D

    operator fun component5(): E

    operator fun component6(): F

    operator fun component7(): G

    operator fun component8(): H

    operator fun component9(): I
  }
}
