package com.github.traderjoe95.mls.codec

import arrow.core.None
import arrow.core.Some
import com.github.traderjoe95.mls.codec.error.DecoderError.ExtraDataInStream
import com.github.traderjoe95.mls.codec.testing.option
import com.github.traderjoe95.mls.codec.type.OptionalT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.VariantField
import com.github.traderjoe95.mls.codec.type.struct.member.Version
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.codec.type.uint24
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.type.uint64
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.codec.util.toBytes
import com.github.traderjoe95.mls.codec.util.uSize
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.enum
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.uByte
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class DecodeTest : ShouldSpec({
  context("ByteArray.decodeAs(type)") {
    should("decode the ByteArray to the given type if it contains only one serialized object") {
      checkAll(
        Arb.uInt8().map { v -> v.encode() to v },
        Arb.uInt16().map { v -> v.encode() to v },
        Arb.uInt24().map { v -> v.encode() to v },
        Arb.uInt32().map { v -> v.encode() to v },
        Arb.uInt64().map { v -> v.encode() to v },
      ) { (uint8Bytes, uInt8), (uint16Bytes, uInt16), (uint24Bytes, uInt24), (uint32Bytes, uInt32), (uint64Bytes, uInt64) ->
        shouldNotRaise { uint8Bytes.decodeAs(uint8) } shouldBe uInt8
        shouldNotRaise { uint16Bytes.decodeAs(uint16) } shouldBe uInt16
        shouldNotRaise { uint24Bytes.decodeAs(uint24) } shouldBe uInt24
        shouldNotRaise { uint32Bytes.decodeAs(uint32) } shouldBe uInt32
        shouldNotRaise { uint64Bytes.decodeAs(uint64) } shouldBe uInt64
      }

      checkAll(
        Arb.vector(Arb.uInt32(), 4U).map { v ->
          v.fold(byteArrayOf()) { b, uint -> b + uint.encode() } to v
        },
        Arb.vector(Arb.uInt16(), 10U..20U).map { v ->
          v.fold(byteArrayOf((v.size * 2).toByte())) { b, uint -> b + uint.encode() } to v
        },
        Arb.vector(Arb.uInt24(), 0U..128U).map { v ->
          v.fold(shouldNotRaise { V(uint24).encode(v.uSize * 3U) }) { b, uint -> b + uint.encode() } to v
        },
      ) { (fixedVecBytes, fixedVec), (intervalVecBytes, intervalVec), (variableVecBytes, variableVec) ->
        shouldNotRaise { fixedVecBytes.decodeAs(uint32[16U]) } shouldBe fixedVec
        shouldNotRaise { intervalVecBytes.decodeAs(uint16[20U..40U]) } shouldBe intervalVec
        shouldNotRaise { variableVecBytes.decodeAs(uint24[V]) } shouldBe variableVec
      }

      checkAll(
        Arb.option(Arb.uInt8()).map { v ->
          when (v) {
            is None -> byteArrayOf(0)
            is Some -> byteArrayOf(1, *v.value.encode())
          } to v
        },
        Arb.option(Arb.uInt16()).map { v ->
          when (v) {
            is None -> byteArrayOf(0)
            is Some -> byteArrayOf(1, *v.value.encode())
          } to v
        },
        Arb.option(Arb.uInt24()).map { v ->
          when (v) {
            is None -> byteArrayOf(0)
            is Some -> byteArrayOf(1, *v.value.encode())
          } to v
        },
      ) { (uint8Bytes, uInt8Opt), (uint16Bytes, uInt16Opt), (uint24Bytes, uInt24Opt) ->
        shouldNotRaise { uint8Bytes.decodeAs(optional[uint8]) } shouldBe uInt8Opt
        shouldNotRaise { uint16Bytes.decodeAs(optional[uint16]) } shouldBe uInt16Opt
        shouldNotRaise { uint24Bytes.decodeAs(optional[uint24]) } shouldBe uInt24Opt
      }

      checkAll(
        Arb.byteArray(16),
        Arb.byteArray(32..64).map { b -> (byteArrayOf(b.size.toByte()) + b) to b },
        Arb.byteArray(0..1024).map { b -> (shouldNotRaise { V(uint8).encode(b.uSize) } + b) to b },
      ) { fixedBytes, (intervalBytes, interval), (variableBytes, variable) ->
        shouldNotRaise { fixedBytes.decodeAs(opaque[16U]) } shouldBe fixedBytes
        shouldNotRaise { intervalBytes.decodeAs(opaque[32U..64U]) } shouldBe interval
        shouldNotRaise { variableBytes.decodeAs(opaque[V]) } shouldBe variable
      }

      checkAll(
        Arb.enum<Version>().filter(ProtocolEnum<*>::isValid).map { e -> e.ord.first.toBytes(1U) to e },
        Arb.enum<OptionalT.Presence>().map { e -> e.ord.first.toBytes(1U) to e },
      ) { (versionBytes, version), (presenceBytes, presence) ->
        shouldNotRaise { versionBytes.decodeAs(Version.T) } shouldBe version
        shouldNotRaise { presenceBytes.decodeAs(OptionalT.Presence.T) } shouldBe presence
      }

      val struct1 =
        shouldNotRaise {
          struct("Struct1") {
            it.field("uint8", uint8)
              .field("optionalUInt", optional[uint32.asUInt])
              .field("bytes", opaque[V])
              .field("coordinates", uint8[3U])
          }
        }

      checkAll(
        Arb.struct(
          Arb.uInt8(),
          Arb.option(Arb.uInt()),
          Arb.byteArray(0..1024),
          Arb.vector(Arb.uInt8(), 3U),
        ).map { s -> shouldNotRaise { struct1.encode(s) } to s },
        Arb.choice(
          Arb.byteArray(32..64).map(::v1),
          Arb.bind(Arb.uByte(), Arb.byteArray(32..64), ::v2),
          Arb.bind(Arb.uByte(), Arb.uInt(), Arb.byteArray(32..64), ::v3),
          Arb.bind(Arb.uByte(), Arb.uInt(), Arb.byteArray(32..64), ::v4),
        ).map { s -> shouldNotRaise { struct2.encode(s) } to s },
      ) { (structBytes, struct), (testBytes, test) ->
        shouldNotRaise { structBytes.decodeAs(struct1) }.also {
          it.field1 shouldBe struct.field1
          it.field2 shouldBe struct.field2
          it.field3 shouldBe struct.field3
          it.field4 shouldBe struct.field4
        }

        shouldNotRaise { testBytes.decodeAs(struct2) }.also {
          it.version shouldBe test.version
          it.variant shouldBe test.variant
          it.key shouldBe test.key
        }
      }
    }

    should("raise an error if there is extra data in the byte array") {
      checkAll(
        Arb.uInt8().map(UIntType::encode).flatMap {
          Arb.bind(Arb.constant(it), Arb.byteArray(1..128), ByteArray::plus)
        },
        Arb.uInt16().map(UIntType::encode).flatMap {
          Arb.bind(Arb.constant(it), Arb.byteArray(1..128), ByteArray::plus)
        },
        Arb.uInt24().map(UIntType::encode).flatMap {
          Arb.bind(Arb.constant(it), Arb.byteArray(1..128), ByteArray::plus)
        },
        Arb.uInt32().map(UIntType::encode).flatMap {
          Arb.bind(Arb.constant(it), Arb.byteArray(1..128), ByteArray::plus)
        },
        Arb.uInt64().map(UIntType::encode).flatMap {
          Arb.bind(Arb.constant(it), Arb.byteArray(1..128), ByteArray::plus)
        },
      ) { uint8Bytes, uint16Bytes, uint24Bytes, uint32Bytes, uint64Bytes ->
        shouldRaise<ExtraDataInStream> { uint8Bytes.decodeAs(uint8) } shouldBe ExtraDataInStream(1U, uint8Bytes.uSize - 1U)
        shouldRaise<ExtraDataInStream> { uint16Bytes.decodeAs(uint16) } shouldBe ExtraDataInStream(2U, uint16Bytes.uSize - 2U)
        shouldRaise<ExtraDataInStream> { uint24Bytes.decodeAs(uint24) } shouldBe ExtraDataInStream(3U, uint24Bytes.uSize - 3U)
        shouldRaise<ExtraDataInStream> { uint32Bytes.decodeAs(uint32) } shouldBe ExtraDataInStream(4U, uint32Bytes.uSize - 4U)
        shouldRaise<ExtraDataInStream> { uint64Bytes.decodeAs(uint64) } shouldBe ExtraDataInStream(8U, uint64Bytes.uSize - 8U)
      }

      checkAll(
        Arb.vector(Arb.uInt32(), 4U).map { v ->
          v.fold(byteArrayOf()) { b, uint -> b + uint.encode() }
        }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
        Arb.vector(Arb.uInt16(), 10U..20U).map { v ->
          v.fold(byteArrayOf((v.size * 2).toByte())) { b, uint -> b + uint.encode() }
        }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
        Arb.vector(Arb.uInt24(), 0U..128U).map { v ->
          v.fold(shouldNotRaise { V(uint24).encode(v.uSize * 3U) }) { b, uint -> b + uint.encode() }
        }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
      ) { (fixedVecBytes, fixedSize), (intervalVecBytes, intervalSize), (variableVecBytes, variableSize) ->
        shouldRaise<ExtraDataInStream> {
          fixedVecBytes.decodeAs(uint32[16U])
        } shouldBe ExtraDataInStream(fixedSize, fixedVecBytes.uSize - fixedSize)
        shouldRaise<ExtraDataInStream> {
          intervalVecBytes.decodeAs(uint16[20U..40U])
        } shouldBe ExtraDataInStream(intervalSize, intervalVecBytes.uSize - intervalSize)
        shouldRaise<ExtraDataInStream> {
          variableVecBytes.decodeAs(uint24[V])
        } shouldBe ExtraDataInStream(variableSize, variableVecBytes.uSize - variableSize)
      }

      checkAll(
        Arb.option(Arb.uInt8()).map { v ->
          when (v) {
            is None -> byteArrayOf(0)
            is Some -> byteArrayOf(1, *v.value.encode())
          }
        }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
        Arb.option(Arb.uInt16()).map { v ->
          when (v) {
            is None -> byteArrayOf(0)
            is Some -> byteArrayOf(1, *v.value.encode())
          }
        }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
        Arb.option(Arb.uInt24()).map { v ->
          when (v) {
            is None -> byteArrayOf(0)
            is Some -> byteArrayOf(1, *v.value.encode())
          }
        }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
      ) { (uint8Bytes, uInt8OptSize), (uint16Bytes, uInt16OptSize), (uint24Bytes, uInt24OptSize) ->
        shouldRaise<ExtraDataInStream> {
          uint8Bytes.decodeAs(optional[uint8])
        } shouldBe ExtraDataInStream(uInt8OptSize, uint8Bytes.uSize - uInt8OptSize)
        shouldRaise<ExtraDataInStream> {
          uint16Bytes.decodeAs(optional[uint16])
        } shouldBe ExtraDataInStream(uInt16OptSize, uint16Bytes.uSize - uInt16OptSize)
        shouldRaise<ExtraDataInStream> {
          uint24Bytes.decodeAs(optional[uint24])
        } shouldBe ExtraDataInStream(uInt24OptSize, uint24Bytes.uSize - uInt24OptSize)
      }

      checkAll(
        Arb.byteArray(16).flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus)
        },
        Arb.byteArray(32..64).map { b -> (byteArrayOf(b.size.toByte()) + b) }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
        Arb.byteArray(0..1024).map { b -> (shouldNotRaise { V(uint8).encode(b.uSize) } + b) }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
      ) { fixedBytes, (intervalBytes, intervalSize), (variableBytes, variableSize) ->
        shouldRaise<ExtraDataInStream> {
          fixedBytes.decodeAs(opaque[16U])
        } shouldBe ExtraDataInStream(16U, fixedBytes.uSize - 16U)
        shouldRaise<ExtraDataInStream> {
          intervalBytes.decodeAs(opaque[32U..64U])
        } shouldBe ExtraDataInStream(intervalSize, intervalBytes.uSize - intervalSize)
        shouldRaise<ExtraDataInStream> {
          variableBytes.decodeAs(opaque[V])
        } shouldBe ExtraDataInStream(variableSize, variableBytes.uSize - variableSize)
      }

      checkAll(
        Arb.enum<Version>().filter(ProtocolEnum<*>::isValid).map { e -> e.ord.first.toBytes(1U) }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus)
        },
        Arb.enum<OptionalT.Presence>().map { e -> e.ord.first.toBytes(1U) }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus)
        },
      ) { versionBytes, presenceBytes ->
        shouldRaise<ExtraDataInStream> {
          versionBytes.decodeAs(Version.T)
        } shouldBe ExtraDataInStream(1U, versionBytes.uSize - 1U)
        shouldRaise<ExtraDataInStream> {
          presenceBytes.decodeAs(OptionalT.Presence.T)
        } shouldBe ExtraDataInStream(1U, presenceBytes.uSize - 1U)
      }

      checkAll(
        Arb.struct(
          Arb.uInt8(),
          Arb.option(Arb.uInt()),
          Arb.byteArray(0..1024),
          Arb.vector(Arb.uInt8(), 3U),
        ).map { s -> shouldNotRaise { struct1.encode(s) } }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
        Arb.choice(
          Arb.byteArray(32..64).map(::v1),
          Arb.bind(Arb.uByte(), Arb.byteArray(32..64), ::v2),
          Arb.bind(Arb.uByte(), Arb.uInt(), Arb.byteArray(32..64), ::v3),
          Arb.bind(Arb.uByte(), Arb.uInt(), Arb.byteArray(32..64), ::v4),
        ).map { s -> shouldNotRaise { struct2.encode(s) } }.flatMap { bytes ->
          Arb.bind(Arb.constant(bytes), Arb.byteArray(1..128), ByteArray::plus).map { it to bytes.uSize }
        },
      ) { (structBytes, structSize), (testBytes, testSize) ->
        shouldRaise<ExtraDataInStream> {
          structBytes.decodeAs(struct1)
        } shouldBe ExtraDataInStream(structSize, structBytes.uSize - structSize)

        shouldRaise<ExtraDataInStream> {
          testBytes.decodeAs(struct2)
        } shouldBe ExtraDataInStream(testSize, testBytes.uSize - testSize)
      }
    }
  }
})

val struct1 =
  shouldNotRaise {
    struct("Struct1") {
      it.field("uint8", uint8)
        .field("optionalUInt", optional[uint32.asUInt])
        .field("bytes", opaque[V])
        .field("coordinates", uint8[3U])
    }
  }

data class Test(val version: Version, val variant: VariantField?, val key: ByteArray) :
  Struct3T.Shape<Version, VariantField?, ByteArray>

fun v1(key: ByteArray): Test = Test(Version.V1, null, key)

fun v2(
  uByte: UByte,
  key: ByteArray,
): Test = Test(Version.V2, VariantField.V2Variant(uByte), key)

fun v3(
  uByte: UByte,
  uInt: UInt,
  key: ByteArray,
): Test = Test(Version.V3, VariantField.V3AndV4Variant(uByte, uInt), key)

fun v4(
  uByte: UByte,
  uInt: UInt,
  key: ByteArray,
): Test = Test(Version.V4, VariantField.V3AndV4Variant(uByte, uInt), key)

val struct2 =
  shouldNotRaise {
    struct("Struct2") {
      it.field("version", Version.T)
        .select<VariantField?, _>(Version.T, "version") {
          case(Version.V2).then(VariantField.V2Variant.T, "v2")
            .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T, "v3")
            .orElseNothing()
        }
        .field("key", opaque[32U..64U])
    }.lift(::Test)
  }
