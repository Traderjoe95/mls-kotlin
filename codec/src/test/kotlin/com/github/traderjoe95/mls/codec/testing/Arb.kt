package com.github.traderjoe95.mls.codec.testing

import arrow.core.Option
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.Struct3
import com.github.traderjoe95.mls.codec.Struct4
import com.github.traderjoe95.mls.codec.Struct5
import com.github.traderjoe95.mls.codec.Struct6
import com.github.traderjoe95.mls.codec.Struct7
import com.github.traderjoe95.mls.codec.Struct8
import com.github.traderjoe95.mls.codec.UIntType
import com.github.traderjoe95.mls.codec.struct
import com.github.traderjoe95.mls.codec.uInt16
import com.github.traderjoe95.mls.codec.uInt24
import com.github.traderjoe95.mls.codec.uInt32
import com.github.traderjoe95.mls.codec.uInt64
import com.github.traderjoe95.mls.codec.uInt8
import com.github.traderjoe95.mls.codec.vector
import io.kotest.property.Arb
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.orNull

// Miscellaneous
fun Arb.Companion.anyUInt(): Arb<UIntType> =
  Arb.choice(
    Arb.uInt8(),
    Arb.uInt16(),
    Arb.uInt24(),
    Arb.uInt32(),
    Arb.uInt64(),
  )

fun <V : Any> Arb.Companion.option(
  values: Arb<V>,
  noneProbability: Double = 0.1,
): Arb<Option<V>> = values.orNull(noneProbability).map { Option.fromNullable(it) }

fun Arb.Companion.anyValue(): Arb<Any> =
  Arb.choice(
    anyUInt(),
    option(Arb.anyUInt()),
    vector(anyUInt(), 0U..256U),
  )

fun Arb.Companion.anyStruct1(): Arb<Struct1<Any>> = struct(anyValue())

fun Arb.Companion.anyStruct2(): Arb<Struct2<Any, Any>> = struct(anyValue(), anyValue())

fun Arb.Companion.anyStruct3(): Arb<Struct3<Any, Any, Any>> = struct(anyValue(), anyValue(), anyValue())

fun Arb.Companion.anyStruct4(): Arb<Struct4<Any, Any, Any, Any>> = struct(anyValue(), anyValue(), anyValue(), anyValue())

fun Arb.Companion.anyStruct5(): Arb<Struct5<Any, Any, Any, Any, Any>> = struct(anyValue(), anyValue(), anyValue(), anyValue(), anyValue())

fun Arb.Companion.anyStruct6(): Arb<Struct6<Any, Any, Any, Any, Any, Any>> =
  struct(anyValue(), anyValue(), anyValue(), anyValue(), anyValue(), anyValue())

fun Arb.Companion.anyStruct7(): Arb<Struct7<Any, Any, Any, Any, Any, Any, Any>> =
  struct(anyValue(), anyValue(), anyValue(), anyValue(), anyValue(), anyValue(), anyValue())

fun Arb.Companion.anyStruct8(): Arb<Struct8<Any, Any, Any, Any, Any, Any, Any, Any>> =
  struct(anyValue(), anyValue(), anyValue(), anyValue(), anyValue(), anyValue(), anyValue(), anyValue())
