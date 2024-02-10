package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.None
import arrow.core.Some
import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.struct
import com.github.traderjoe95.mls.codec.testing.option
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.FixedLength
import com.github.traderjoe95.mls.codec.type.OpaqueT
import com.github.traderjoe95.mls.codec.type.OptionalT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.VariableLength
import com.github.traderjoe95.mls.codec.type.asUtf8String
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.member.Field
import com.github.traderjoe95.mls.codec.type.struct.member.Version
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.codec.type.uint24
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.type.uint64
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.codec.uInt16
import com.github.traderjoe95.mls.codec.uInt24
import com.github.traderjoe95.mls.codec.uInt32
import com.github.traderjoe95.mls.codec.uInt64
import com.github.traderjoe95.mls.codec.uInt8
import com.github.traderjoe95.mls.codec.util.toBytes
import com.github.traderjoe95.mls.codec.util.uSize
import io.kotest.assertions.arrow.core.shouldBeNone
import io.kotest.assertions.arrow.core.shouldBeSome
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.kotest.property.Arb
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.alphanumeric
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.enum
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.uShort
import io.kotest.property.checkAll

class Struct8TTest : ShouldSpec({
  context("Struct8T<A, B, C, D, E, F, G, H>") {
    val struct1 =
      struct("TestStruct1") {
        it.field("uint8Constant", uint8, uint8(1U))
          .field("uint16", uint16.asUShort)
          .field("uint8", uint8)
          .field("uint24", uint24)
          .field("uint32", uint32)
          .field("uint64", uint64)
          .field("version", Version.T)
          .field("threeBytes", opaque[3U].asUtf8String)
      }
    val arbS1 =
      Arb.struct(
        Arb.constant(uint8(1U)),
        Arb.uShort(),
        Arb.uInt8(),
        Arb.uInt24(),
        Arb.uInt32(),
        Arb.uInt64(),
        Arb.enum<Version>().filter(ProtocolEnum<*>::isValid),
        Arb.string(3, Codepoint.alphanumeric()),
      )

    val struct2 =
      shouldNotRaise {
        struct("TestStruct2") {
          it.field("bytes", opaque[V])
            .field("uint8", uint8)
            .field("uint16", uint16)
            .field("uint24", uint24)
            .field("uint32", uint32)
            .field("uint64", uint64)
            .field("version", Version.T)
            .field("threeBytes", opaque[3U].asUtf8String)
        }
      }
    val arbS2 =
      Arb.struct(
        Arb.byteArray(0..1024),
        Arb.uInt8(),
        Arb.uInt16(),
        Arb.uInt24(),
        Arb.uInt32(),
        Arb.uInt64(),
        Arb.enum<Version>().filter(ProtocolEnum<*>::isValid),
        Arb.string(3, Codepoint.alphanumeric()),
      )

    val struct3 =
      shouldNotRaise {
        struct("TestStruct3") {
          it.field("uint8", uint8)
            .field("uint16", uint16)
            .field("uint24", uint24)
            .field("uint32", uint32)
            .field("uint64", uint64)
            .field("version", Version.T)
            .field("threeBytes", opaque[3U].asUtf8String)
            .field("optionalUInt", optional[uint32])
        }
      }
    val arbS3 =
      Arb.struct(
        Arb.uInt8(),
        Arb.uInt16(),
        Arb.uInt24(),
        Arb.uInt32(),
        Arb.uInt64(),
        Arb.enum<Version>().filter(ProtocolEnum<*>::isValid),
        Arb.string(3, Codepoint.alphanumeric()),
        Arb.option(Arb.uInt32()),
      )

    context(".encode(value)") {
      should("return the concatenation of all field's encodings in order") {
        checkAll(arbS1, arbS2, arbS3) { s1, s2, s3 ->
          shouldNotRaise {
            struct1.encode(s1)
          } shouldBe
            byteArrayOf(
              *s1.field1.encode(),
              *uint16(s1.field2).encode(),
              *s1.field3.encode(),
              *s1.field4.encode(),
              *s1.field5.encode(),
              *s1.field6.encode(),
              *s1.field7.ord.first.toBytes(1U),
              *s1.field8.encodeToByteArray(),
            )

          shouldNotRaise {
            struct2.encode(s2)
          } shouldBe
            byteArrayOf(
              *shouldNotRaise { V(uint8).encode(s2.field1.uSize) },
              *s2.field1,
              *s2.field2.encode(),
              *s2.field3.encode(),
              *s2.field4.encode(),
              *s2.field5.encode(),
              *s2.field6.encode(),
              *s2.field7.ord.first.toBytes(1U),
              *s2.field8.encodeToByteArray(),
            )

          shouldNotRaise { struct3.encode(s3) } shouldBe
            byteArrayOf(
              *s3.field1.encode(),
              *s3.field2.encode(),
              *s3.field3.encode(),
              *s3.field4.encode(),
              *s3.field5.encode(),
              *s3.field6.ord.first.toBytes(1U),
              *s3.field7.encodeToByteArray(),
              *when (val opt = s3.field8) {
                is None -> byteArrayOf(0)
                is Some -> byteArrayOf(1, *opt.value.encode())
              },
            )
        }
      }
    }

    context(".decode(bytes)") {
      should("decode the single field and return it in a Struct1") {
        checkAll(
          arbS1.flatMap { s1 ->
            Arb.slice(
              shouldNotRaise { struct1.encode(s1) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s1 }
          },
          arbS2.flatMap { s2 ->
            Arb.slice(
              shouldNotRaise { struct2.encode(s2) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s2 }
          },
          arbS3.flatMap { s3 ->
            Arb.slice(
              shouldNotRaise { struct3.encode(s3) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s3 }
          },
        ) { (slice1, s1), (slice2, s2), (slice3, s3) ->
          shouldNotRaise { struct1.decode(slice1) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice1.firstIndex + 23U
            remaining.lastIndex shouldBe slice1.lastIndex

            decoded shouldBe s1
          }

          shouldNotRaise { struct2.decode(slice2) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice2.firstIndex +
              shouldNotRaise {
                V(uint8).encode(s2.field1.uSize).uSize
              } + s2.field1.uSize + 22U
            remaining.lastIndex shouldBe slice2.lastIndex

            decoded.field1 shouldBe s2.field1
            decoded.field2 shouldBe s2.field2
            decoded.field3 shouldBe s2.field3
            decoded.field4 shouldBe s2.field4
            decoded.field5 shouldBe s2.field5
            decoded.field6 shouldBe s2.field6
            decoded.field7 shouldBe s2.field7
            decoded.field8 shouldBe s2.field8
          }

          shouldNotRaise { struct3.decode(slice3) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice3.firstIndex + 22U +
              when (s3.field8) {
                is None -> 1U
                is Some -> 5U
              }
            remaining.lastIndex shouldBe slice3.lastIndex

            decoded shouldBe s3
          }
        }
      }
    }

    context(".create(field1, field2)") {
      should("return Struct2(field1, field2)") {
        checkAll(arbS1, arbS2, arbS3) { s1, s2, s3 ->
          struct1.create(s1.field1, s1.field2, s1.field3, s1.field4, s1.field5, s1.field6, s1.field7, s1.field8) shouldBe s1
          struct2.create(s2.field1, s2.field2, s2.field3, s2.field4, s2.field5, s2.field6, s2.field7, s2.field8) shouldBe s2
          struct3.create(s3.field1, s3.field2, s3.field3, s3.field4, s3.field5, s3.field6, s3.field7, s3.field8) shouldBe s3
        }
      }
    }

    context(".name") {
      should("should be the name passed to the struct builder") {
        struct1.name shouldBe "TestStruct1"
        struct2.name shouldBe "TestStruct2"
        struct3.name shouldBe "TestStruct3"
      }
    }

    context(".encodedLength") {
      should("should be the sum of all field lengths if all fields have a defined length") {
        struct1.encodedLength shouldBe 23U
      }

      should("should be null if any field does not have a defined length") {
        struct2.encodedLength.shouldBeNull()
        struct3.encodedLength.shouldBeNull()
      }
    }

    context(".members") {
      should("should contain all fields in order") {
        struct1.members.size shouldBe 8
        struct1.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint8Constant"
          it.type shouldBe uint8
          it.index shouldBe 0U
          it.constant shouldBeSome uint8(1U)
          it.checkedType.shouldBeNull()
        }
        struct1.members[1].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint16"
          it.type shouldBe uint16.asUShort
          it.index shouldBe 1U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct1.members[2].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint8"
          it.type shouldBe uint8
          it.index shouldBe 2U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct1.members[3].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint24"
          it.type shouldBe uint24
          it.index shouldBe 3U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct1.members[4].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint32"
          it.type shouldBe uint32
          it.index shouldBe 4U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct1.members[5].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint64"
          it.type shouldBe uint64
          it.index shouldBe 5U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct1.members[6].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "version"
          it.type shouldBe Version.T
          it.index shouldBe 6U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct1.members[7].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "threeBytes"
          it.type.shouldBeInstanceOf<DataType.Derived<*, *>>().base
            .shouldBeInstanceOf<OpaqueT>().length
            .shouldBeInstanceOf<FixedLength>().fixedLength shouldBe 3U
          it.index shouldBe 7U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }

        struct2.members.size shouldBe 8
        struct2.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "bytes"
          it.type.shouldBeInstanceOf<OpaqueT>().length.shouldBeInstanceOf<VariableLength>().mod shouldBe 1U
          it.index shouldBe 0U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct2.members[1].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint8"
          it.type shouldBe uint8
          it.index shouldBe 1U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct2.members[2].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint16"
          it.type shouldBe uint16
          it.index shouldBe 2U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct2.members[3].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint24"
          it.type shouldBe uint24
          it.index shouldBe 3U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct2.members[4].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint32"
          it.type shouldBe uint32
          it.index shouldBe 4U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct2.members[5].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint64"
          it.type shouldBe uint64
          it.index shouldBe 5U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct2.members[6].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "version"
          it.type shouldBe Version.T
          it.index shouldBe 6U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct2.members[7].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "threeBytes"
          it.type.shouldBeInstanceOf<DataType.Derived<*, *>>().base
            .shouldBeInstanceOf<OpaqueT>().length
            .shouldBeInstanceOf<FixedLength>().fixedLength shouldBe 3U
          it.index shouldBe 7U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }

        struct3.members.size shouldBe 8
        struct3.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint8"
          it.type shouldBe uint8
          it.index shouldBe 0U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct3.members[1].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint16"
          it.type shouldBe uint16
          it.index shouldBe 1U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct3.members[2].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint24"
          it.type shouldBe uint24
          it.index shouldBe 2U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct3.members[3].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint32"
          it.type shouldBe uint32
          it.index shouldBe 3U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct3.members[4].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint64"
          it.type shouldBe uint64
          it.index shouldBe 4U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct3.members[5].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "version"
          it.type shouldBe Version.T
          it.index shouldBe 5U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct3.members[6].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "threeBytes"
          it.type.shouldBeInstanceOf<DataType.Derived<*, *>>().base
            .shouldBeInstanceOf<OpaqueT>().length
            .shouldBeInstanceOf<FixedLength>().fixedLength shouldBe 3U
          it.index shouldBe 6U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
        struct3.members[7].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "optionalUInt"
          it.type.shouldBeInstanceOf<OptionalT<*>>().valueType shouldBe uint32
          it.index shouldBe 7U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
      }
    }

    context("get(fieldName)") {
      should("return the field if the name exists") {
        struct1["uint8Constant"] shouldBeSameInstanceAs struct1.members[0]
        struct1["uint16"] shouldBeSameInstanceAs struct1.members[1]
        struct1["uint8"] shouldBeSameInstanceAs struct1.members[2]
        struct1["uint24"] shouldBeSameInstanceAs struct1.members[3]
        struct1["uint32"] shouldBeSameInstanceAs struct1.members[4]
        struct1["uint64"] shouldBeSameInstanceAs struct1.members[5]
        struct1["version"] shouldBeSameInstanceAs struct1.members[6]
        struct1["threeBytes"] shouldBeSameInstanceAs struct1.members[7]

        struct2["bytes"] shouldBeSameInstanceAs struct2.members[0]
        struct2["uint8"] shouldBeSameInstanceAs struct2.members[1]
        struct2["uint16"] shouldBeSameInstanceAs struct2.members[2]
        struct2["uint24"] shouldBeSameInstanceAs struct2.members[3]
        struct2["uint32"] shouldBeSameInstanceAs struct2.members[4]
        struct2["uint64"] shouldBeSameInstanceAs struct2.members[5]
        struct2["version"] shouldBeSameInstanceAs struct2.members[6]
        struct2["threeBytes"] shouldBeSameInstanceAs struct2.members[7]

        struct3["uint8"] shouldBeSameInstanceAs struct3.members[0]
        struct3["uint16"] shouldBeSameInstanceAs struct3.members[1]
        struct3["uint24"] shouldBeSameInstanceAs struct3.members[2]
        struct3["uint32"] shouldBeSameInstanceAs struct3.members[3]
        struct3["uint64"] shouldBeSameInstanceAs struct3.members[4]
        struct3["version"] shouldBeSameInstanceAs struct3.members[5]
        struct3["threeBytes"] shouldBeSameInstanceAs struct3.members[6]
        struct3["optionalUInt"] shouldBeSameInstanceAs struct3.members[7]
      }

      should("return null if the field does not exist") {
        checkAll(
          Arb.string(1..32, Codepoint.alphanumeric())
            .filter { it !in setOf("uint8Constant", "uint8", "uint16", "uint24", "uint32", "uint64", "version", "threeBytes") },
        ) {
          struct1[it].shouldBeNull()
        }

        checkAll(
          Arb.string(1..32, Codepoint.alphanumeric())
            .filter { it !in setOf("bytes", "uint8", "uint16", "uint24", "uint32", "uint64", "version", "threeBytes") },
        ) {
          struct2[it].shouldBeNull()
        }

        checkAll(
          Arb.string(1..32, Codepoint.alphanumeric())
            .filter { it !in setOf("uint8", "uint16", "optionalUInt", "uint24", "uint32", "uint64", "version", "threeBytes") },
        ) {
          struct3[it].shouldBeNull()
        }
      }
    }
  }
})
