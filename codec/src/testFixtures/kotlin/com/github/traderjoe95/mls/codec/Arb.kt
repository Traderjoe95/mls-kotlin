package com.github.traderjoe95.mls.codec

import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.codec.type.uint24
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.type.uint64
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.partial
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.util.toIntRange
import com.github.traderjoe95.mls.codec.util.uSize
import io.kotest.property.Arb
import io.kotest.property.Gen
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.printableAscii
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.uByte
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.arbitrary.uShort

// Integers
fun Arb.Companion.uInt8(): Arb<UInt8> = uByte().map(uint8::invoke)

fun Arb.Companion.uInt16(): Arb<UInt16> = uShort().map(uint16::invoke)

fun Arb.Companion.uInt24(): Arb<UInt24> = uInt(0U..0xFFFFFFU).map { throwAnyError { uint24(it) } }

fun Arb.Companion.uInt32(): Arb<UInt32> = uInt().map(uint32::invoke)

fun Arb.Companion.uInt64(): Arb<UInt64> = uLong().map(uint64::invoke)

fun Arb.Companion.uIntRange(
  min: UIntRange,
  max: UIntRange,
  allowEmpty: Boolean = false,
) = uIntRange(Arb.uInt(min), Arb.uInt(max), allowEmpty)

fun Arb.Companion.uIntRange(
  min: Gen<UInt>,
  max: Gen<UInt>,
  allowEmpty: Boolean = false,
) = Arb.bind(min, max, UInt::rangeTo).filter { allowEmpty || !it.isEmpty() }

fun Arb<UInt>.toInt(): Arb<Int> = map { it.toInt() }

// Vectors
fun <V> Arb.Companion.vector(
  values: Arb<V>,
  length: UInt,
): Arb<List<V>> = Arb.list(values, length.toInt()..length.toInt())

fun <V> Arb.Companion.vector(
  values: Arb<V>,
  length: UIntRange,
): Arb<List<V>> = Arb.list(values, length.toIntRange())

val v1Byte: UIntRange = 0x00U..0x3FU
val v2Bytes: UIntRange = 0x40U..0x3FFFU
val v4Bytes: UIntRange = 0x4000U..0x3FFFFFFFU

// Structs
fun <A> Arb.Companion.struct(field1: Arb<A>): Arb<Struct1<A>> = field1.map(::Struct1)

fun <A, B> Arb.Companion.struct(
  field1: Arb<A>,
  field2: Arb<B>,
): Arb<Struct2<A, B>> = bind(field1, field2, ::Struct2)

fun <A, B, C> Arb.Companion.struct(
  field1: Arb<A>,
  field2: Arb<B>,
  field3: Arb<C>,
): Arb<Struct3<A, B, C>> = bind(field1, field2, field3, ::Struct3)

fun <A, B, C, D> Arb.Companion.struct(
  field1: Arb<A>,
  field2: Arb<B>,
  field3: Arb<C>,
  field4: Arb<D>,
): Arb<Struct4<A, B, C, D>> = bind(field1, field2, field3, field4, ::Struct4)

fun <A, B, C, D, E> Arb.Companion.struct(
  field1: Arb<A>,
  field2: Arb<B>,
  field3: Arb<C>,
  field4: Arb<D>,
  field5: Arb<E>,
): Arb<Struct5<A, B, C, D, E>> = bind(field1, field2, field3, field4, field5, ::Struct5)

fun <A, B, C, D, E, F> Arb.Companion.struct(
  field1: Arb<A>,
  field2: Arb<B>,
  field3: Arb<C>,
  field4: Arb<D>,
  field5: Arb<E>,
  field6: Arb<F>,
): Arb<Struct6<A, B, C, D, E, F>> = bind(field1, field2, field3, field4, field5, field6, ::Struct6)

fun <A, B, C, D, E, F, G> Arb.Companion.struct(
  field1: Arb<A>,
  field2: Arb<B>,
  field3: Arb<C>,
  field4: Arb<D>,
  field5: Arb<E>,
  field6: Arb<F>,
  field7: Arb<G>,
): Arb<Struct7<A, B, C, D, E, F, G>> = bind(field1, field2, field3, field4, field5, field6, field7, ::Struct7)

@Suppress("kotlin:S107")
fun <A, B, C, D, E, F, G, H> Arb.Companion.struct(
  field1: Arb<A>,
  field2: Arb<B>,
  field3: Arb<C>,
  field4: Arb<D>,
  field5: Arb<E>,
  field6: Arb<F>,
  field7: Arb<G>,
  field8: Arb<H>,
): Arb<Struct8<A, B, C, D, E, F, G, H>> = bind(field1, field2, field3, field4, field5, field6, field7, field8, ::Struct8)

// Byte Arrays
fun Arb.Companion.byteArray(length: Int): Arb<ByteArray> = byteArray(length, byte())

fun Arb.Companion.byteArray(length: IntRange): Arb<ByteArray> = byteArray(int(length))

fun Arb.Companion.byteArray(
  length: Int,
  content: Arb<Byte>,
): Arb<ByteArray> = byteArray(length..length, content)

fun Arb.Companion.byteArray(
  length: IntRange,
  content: Arb<Byte>,
): Arb<ByteArray> = byteArray(int(length), content)

fun Arb.Companion.byteArray(length: Gen<Int>): Arb<ByteArray> = byteArray(length, Arb.byte())

fun Arb.Companion.byteArrayWithV(
  length: Gen<Int>,
  content: Arb<Byte> = byte(),
): Arb<Triple<ByteArray, ByteArray, UInt>> =
  byteArray(length, content).map {
    throwAnyError {
      Triple(byteArrayOf(*V(uint8).encode(it.uSize), *it), it, it.uSize)
    }
  }

fun Arb.Companion.stringWithV(
  length: IntRange,
  codepoint: Arb<Codepoint> = Codepoint.printableAscii(),
): Arb<Triple<ByteArray, String, UInt>> =
  string(length, codepoint).map {
    throwAnyError {
      Triple(byteArrayOf(*V(uint8).encode(it.uSize), *it.encodeToByteArray()), it, it.uSize)
    }
  }

// Slices
fun Arb.Companion.slice(
  availableBytes: ByteArray,
  alreadyConsumedLength: UIntRange = 0U..0U,
  extraLength: UIntRange = 0U..0U,
): Arb<Slice> = slice(availableBytes, uInt(alreadyConsumedLength), uInt(extraLength))

fun Arb.Companion.slice(
  availableBytes: ByteArray,
  alreadyConsumedLength: Arb<UInt>,
  extraLength: Arb<UInt>,
): Arb<Slice> = slice(constant(availableBytes), alreadyConsumedLength, extraLength)

fun Arb.Companion.slice(
  availableBytes: Gen<ByteArray>,
  alreadyConsumedLength: UIntRange = 0U..0U,
  extraLength: UIntRange = 0U..0U,
): Arb<Slice> = slice(availableBytes, uInt(alreadyConsumedLength), uInt(extraLength))

fun Arb.Companion.slice(
  availableBytes: Gen<ByteArray>,
  alreadyConsumedLength: Arb<UInt>,
  extraLength: Arb<UInt>,
): Arb<Slice> =
  bind(
    byteArray(alreadyConsumedLength.toInt(), byte()),
    availableBytes,
    byteArray(extraLength.toInt(), byte()),
  ) { prefix, bytes, postfix ->
    shouldNotRaise { (prefix + bytes + postfix).partial(prefix.uSize) }
  }

fun <V> Arb.Companion.partition(set: Set<V>): Arb<Pair<Set<V>, Set<V>>> =
  arbitrary {
    val left = mutableSetOf<V>()
    val right = mutableSetOf<V>()

    set.forEach {
      if (boolean().bind()) left.add(it) else right.add(it)
    }

    left to right
  }

fun <V> Arb.Companion.subset(set: Set<V>): Arb<Set<V>> =
  arbitrary {
    val result = mutableSetOf<V>()

    set.forEach {
      if (boolean().bind()) result.add(it)
    }

    result
  }
