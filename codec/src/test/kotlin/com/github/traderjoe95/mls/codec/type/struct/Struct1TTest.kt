package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.None
import arrow.core.Some
import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.struct
import com.github.traderjoe95.mls.codec.testing.option
import com.github.traderjoe95.mls.codec.type.FixedLength
import com.github.traderjoe95.mls.codec.type.OpaqueT
import com.github.traderjoe95.mls.codec.type.OptionalT
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.VariableLength
import com.github.traderjoe95.mls.codec.type.VectorT
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.member.Field
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.codec.uInt32
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.codec.vector
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
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.uByte
import io.kotest.property.arbitrary.uShort
import io.kotest.property.checkAll

class Struct1TTest : ShouldSpec({
  context("Struct1T<A>") {
    val struct1 =
      struct("TestStruct1") {
        it.field("uint8", uint8, uint8(1U))
      }

    val struct2 =
      struct("TestStruct2") {
        it.field("uint16", uint16.asUShort)
      }

    val struct3 =
      shouldNotRaise {
        struct("TestStruct3") {
          it.field("uint8V", uint8.asUByte[4U])
        }
      }

    val struct4 =
      shouldNotRaise {
        struct("TestStruct4") {
          it.field("bytes", opaque[V])
        }
      }

    val struct5 =
      shouldNotRaise {
        struct("TestStruct5") {
          it.field("optionalUInt", optional[uint32])
        }
      }

    context(".encode(value)") {
      should("return the encoding of the single field") {
        checkAll(
          Arb.struct(Arb.constant(uint8(1U))),
          Arb.struct(Arb.uShort()),
          Arb.struct(Arb.vector(Arb.uByte(), 4U)),
          Arb.struct(Arb.byteArray(0..1024)),
          Arb.struct(Arb.option(Arb.uInt32())),
        ) { s1, s2, s3, s4, s5 ->
          shouldNotRaise { struct1.encode(s1) } shouldBe s1.field1.encode()
          shouldNotRaise { struct2.encode(s2) } shouldBe uint16(s2.field1).encode()
          shouldNotRaise { struct3.encode(s3) } shouldBe s3.field1.map { it.toByte() }.toByteArray()

          shouldNotRaise { struct4.encode(s4) } shouldBe
            byteArrayOf(
              *shouldNotRaise { V(uint8).encode(s4.field1.uSize) },
              *s4.field1,
            )

          shouldNotRaise { struct5.encode(s5) } shouldBe
            when (val opt = s5.field1) {
              is None -> byteArrayOf(0)
              is Some -> byteArrayOf(1, *opt.value.encode())
            }
        }
      }
    }

    context(".decode(bytes)") {
      should("decode the single field and return it in a Struct1") {
        checkAll(
          Arb.struct(Arb.constant(uint8(1U))).flatMap { s1 ->
            Arb.slice(
              shouldNotRaise { struct1.encode(s1) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s1 }
          },
          Arb.struct(Arb.uShort()).flatMap { s2 ->
            Arb.slice(
              shouldNotRaise { struct2.encode(s2) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s2 }
          },
          Arb.struct(Arb.vector(Arb.uByte(), 4U)).flatMap { s3 ->
            Arb.slice(
              shouldNotRaise { struct3.encode(s3) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s3 }
          },
          Arb.struct(Arb.byteArray(0..1024)).flatMap { s4 ->
            Arb.slice(
              shouldNotRaise { struct4.encode(s4) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s4 }
          },
          Arb.struct(Arb.option(Arb.uInt32())).flatMap { s5 ->
            Arb.slice(
              shouldNotRaise { struct5.encode(s5) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s5 }
          },
        ) { (slice1, s1), (slice2, s2), (slice3, s3), (slice4, s4), (slice5, s5) ->
          shouldNotRaise { struct1.decode(slice1) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice1.firstIndex + 1U
            remaining.lastIndex shouldBe slice1.lastIndex

            decoded shouldBe s1
          }

          shouldNotRaise { struct2.decode(slice2) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice2.firstIndex + 2U
            remaining.lastIndex shouldBe slice2.lastIndex

            decoded shouldBe s2
          }

          shouldNotRaise { struct3.decode(slice3) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice3.firstIndex + 4U
            remaining.lastIndex shouldBe slice3.lastIndex

            decoded shouldBe s3
          }

          shouldNotRaise { struct4.decode(slice4) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice4.firstIndex + shouldNotRaise { V(uint8).encode(s4.field1.uSize).uSize } + s4.field1.uSize
            remaining.lastIndex shouldBe slice4.lastIndex

            decoded.field1 shouldBe s4.field1
          }

          shouldNotRaise { struct5.decode(slice5) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe slice5.firstIndex +
              when (s5.field1) {
                is None -> 1U
                is Some -> 5U
              }
            remaining.lastIndex shouldBe slice5.lastIndex

            decoded shouldBe s5
          }
        }
      }
    }

    context(".create(field1)") {
      should("return Struct1(field1)") {
        checkAll(
          Arb.struct(Arb.constant(uint8(1U))),
          Arb.struct(Arb.uShort()),
          Arb.struct(Arb.vector(Arb.uByte(), 4U)),
          Arb.struct(Arb.byteArray(0..1024)),
          Arb.struct(Arb.option(Arb.uInt32())),
        ) { s1, s2, s3, s4, s5 ->
          struct1.create(s1.field1) shouldBe s1
          struct2.create(s2.field1) shouldBe s2
          struct3.create(s3.field1) shouldBe s3
          struct4.create(s4.field1) shouldBe s4
          struct5.create(s5.field1) shouldBe s5
        }
      }
    }

    context(".name") {
      should("should be the name passed to the struct builder") {
        struct1.name shouldBe "TestStruct1"
        struct2.name shouldBe "TestStruct2"
        struct3.name shouldBe "TestStruct3"
        struct4.name shouldBe "TestStruct4"
        struct5.name shouldBe "TestStruct5"
      }
    }

    context(".encodedLength") {
      should("should be the single field length if it has a defined length") {
        struct1.encodedLength shouldBe 1U
        struct2.encodedLength shouldBe 2U
        struct3.encodedLength shouldBe 4U
      }

      should("should be null if the field does not have a defined length") {
        struct4.encodedLength.shouldBeNull()
        struct5.encodedLength.shouldBeNull()
      }
    }

    context(".members") {
      should("should contain the single field") {
        struct1.members.size shouldBe 1
        struct1.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint8"
          it.type shouldBe uint8
          it.index shouldBe 0U
          it.constant shouldBeSome uint8(1U)
          it.checkedType.shouldBeNull()
        }

        struct2.members.size shouldBe 1
        struct2.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint16"
          it.type shouldBe uint16.asUShort
          it.index shouldBe 0U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }

        struct3.members.size shouldBe 1
        struct3.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "uint8V"
          it.type.shouldBeInstanceOf<VectorT<*>>().also { v ->
            v.length.shouldBeInstanceOf<FixedLength>().fixedLength shouldBe 4U
            v.componentType shouldBe uint8.asUByte
          }
          it.index shouldBe 0U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }

        struct4.members.size shouldBe 1
        struct4.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "bytes"
          it.type.shouldBeInstanceOf<OpaqueT>().length.shouldBeInstanceOf<VariableLength>().mod shouldBe 1U
          it.index shouldBe 0U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }

        struct5.members.size shouldBe 1
        struct5.members[0].shouldBeInstanceOf<Field<*>>().also {
          it.name shouldBe "optionalUInt"
          it.type.shouldBeInstanceOf<OptionalT<*>>().valueType shouldBe uint32
          it.index shouldBe 0U
          it.constant.shouldBeNone()
          it.checkedType.shouldBeNull()
        }
      }
    }

    context("get(fieldName)") {
      should("return the field if the name exists") {
        struct1["uint8"] shouldBeSameInstanceAs struct1.members[0]
        struct2["uint16"] shouldBeSameInstanceAs struct2.members[0]
        struct3["uint8V"] shouldBeSameInstanceAs struct3.members[0]
        struct4["bytes"] shouldBeSameInstanceAs struct4.members[0]
        struct5["optionalUInt"] shouldBeSameInstanceAs struct5.members[0]
      }

      should("return null if the field does not exist") {
        checkAll(Arb.string(1..32, Codepoint.alphanumeric()).filter { it != "uint8" }) {
          struct1[it].shouldBeNull()
        }

        checkAll(Arb.string(1..32, Codepoint.alphanumeric()).filter { it != "uint16" }) {
          struct2[it].shouldBeNull()
        }

        checkAll(Arb.string(1..32, Codepoint.alphanumeric()).filter { it != "uint8V" }) {
          struct3[it].shouldBeNull()
        }

        checkAll(Arb.string(1..32, Codepoint.alphanumeric()).filter { it != "bytes" }) {
          struct4[it].shouldBeNull()
        }

        checkAll(Arb.string(1..32, Codepoint.alphanumeric()).filter { it != "optionalUInt" }) {
          struct5[it].shouldBeNull()
        }
      }
    }
  }
})
