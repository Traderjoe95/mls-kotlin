package com.github.traderjoe95.mls.codec.type.struct.member

import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.UInt8
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.type.struct.member.Field.Companion.ofType
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.codec.uInt8
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.uShort
import io.kotest.property.checkAll

@Suppress("UNCHECKED_CAST")
class FieldTest : ShouldSpec({
  context("Field<V>") {

    context("without a constant value") {
      val testStruct =
        struct("Test") {
          it.field("uint8", uint8)
            .field("uShort", uint16.asUShort)
        }

      context("with a checked type") {
        val fUInt8 = "uint8".ofType(uint8, 0U, checkedType = UInt8::class)
        val fUShort = "uShort".ofType(uint16.asUShort, 1U, checkedType = UShort::class)

        context(".encodeValue(value, _, structT)") {
          should("encode the value if it is of the correct type") {
            checkAll(Arb.uInt8(), Arb.uShort()) { uint8, ushort ->
              shouldNotRaise {
                fUInt8.encodeValue(uint8, Struct2(uint8, ushort), testStruct)
              } shouldBe uint8.encode()

              shouldNotRaise {
                fUShort.encodeValue(ushort, Struct2(uint8, ushort), testStruct)
              } shouldBe uint16(ushort).encode()
            }
          }

          should("raise an error if the value is of a wrong type") {
            checkAll(Arb.uInt8(), Arb.uShort()) { uint8, ushort ->
              shouldRaise<EncoderError.WrongVariant> {
                (fUInt8 as Field<Any?>).encodeValue(ushort, Struct2(uint8, ushort), testStruct)
              } shouldBe EncoderError.WrongVariant(testStruct.name, 0U, "uint8", ushort)

              shouldRaise<EncoderError.WrongVariant> {
                (fUShort as Field<Any?>).encodeValue(uint8, Struct2(uint8, ushort), testStruct)
              } shouldBe EncoderError.WrongVariant(testStruct.name, 1U, "uint16", uint8)
            }
          }
        }
      }

      context("without a checked type") {
        val fUInt8 = "uint8".ofType(uint8, 0U)
        val fUShort = "testField".ofType(uint16.asUShort, 1U)

        context(".encodeValue(value, _, structT)") {
          should("encode the value if it is of the correct type") {
            checkAll(Arb.uInt8(), Arb.uShort()) { uint8, ushort ->
              shouldNotRaise {
                fUInt8.encodeValue(uint8, Struct2(uint8, ushort), testStruct)
              } shouldBe uint8.encode()

              shouldNotRaise {
                fUShort.encodeValue(ushort, Struct2(uint8, ushort), testStruct)
              } shouldBe uint16(ushort).encode()
            }
          }
        }
      }
    }

    context("with a constant value") {
      context("with a checked type") {
        context(".encodeValue(value, _, structT)") {
          should("encode the value if it is of the correct type and equal to the constant") {
            checkAll(Arb.uInt8(), Arb.uShort()) { ubyte, ushort ->
              val fUInt8 = "uint8".ofType(uint8, 0U, checkedType = UInt8::class, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, checkedType = UShort::class, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldNotRaise {
                fUInt8.encodeValue(ubyte, Struct2(ubyte, ushort), testStruct)
              } shouldBe ubyte.encode()

              shouldNotRaise {
                fUShort.encodeValue(ushort, Struct2(ubyte, ushort), testStruct)
              } shouldBe uint16(ushort).encode()
            }
          }

          should("raise an error if the value is of a wrong type") {
            checkAll(Arb.uInt8(), Arb.uShort()) { ubyte, ushort ->
              val fUInt8 = "uint8".ofType(uint8, 0U, checkedType = UInt8::class, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, checkedType = UShort::class, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldRaise<EncoderError.WrongVariant> {
                (fUInt8 as Field<Any?>).encodeValue(ushort, Struct2(ubyte, ushort), testStruct)
              } shouldBe EncoderError.WrongVariant(testStruct.name, 0U, "uint8", ushort)

              shouldRaise<EncoderError.WrongVariant> {
                (fUShort as Field<Any?>).encodeValue(uint8, Struct2(ubyte, ushort), testStruct)
              } shouldBe EncoderError.WrongVariant(testStruct.name, 1U, "uint16", uint8)
            }
          }

          should("raise an error if the value is different from the constant") {
            checkAll(
              Arb.pair(Arb.uInt8(), Arb.uInt8()).filter { it.first != it.second },
              Arb.pair(Arb.uShort(), Arb.uShort()).filter { it.first != it.second },
            ) { (ubyte, wrongUByte), (ushort, wrongUShort) ->
              val fUInt8 = "uint8".ofType(uint8, 0U, checkedType = UInt8::class, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, checkedType = UShort::class, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldRaise<EncoderError.InvalidFieldValue> {
                (fUInt8 as Field<Any?>).encodeValue(wrongUByte, Struct2(wrongUByte, ushort), testStruct)
              } shouldBe EncoderError.InvalidFieldValue(testStruct.name, 0U, ubyte, wrongUByte)

              shouldRaise<EncoderError.InvalidFieldValue> {
                (fUShort as Field<Any?>).encodeValue(wrongUShort, Struct2(ubyte, wrongUShort), testStruct)
              } shouldBe EncoderError.InvalidFieldValue(testStruct.name, 1U, ushort, wrongUShort)
            }
          }
        }

        context(".decodeValue(bytes, _, structT") {
          should("decode the value if it is equal to the constant") {
            checkAll(
              Arb.uInt8().flatMap { ubyte ->
                Arb.slice(ubyte.encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { it to ubyte }
              },
              Arb.uShort().flatMap { ushort ->
                Arb.slice(uint16(ushort).encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { it to ushort }
              },
            ) { (uByteSlice, ubyte), (uShortSlice, ushort) ->
              val fUInt8 = "uint8".ofType(uint8, 0U, checkedType = UInt8::class, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, checkedType = UShort::class, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldNotRaise {
                fUInt8.decodeValue(uByteSlice, null, testStruct)
              }.also { (decoded, remaining) ->
                remaining.firstIndex shouldBe uByteSlice.firstIndex + 1U
                remaining.lastIndex shouldBe uByteSlice.lastIndex

                decoded shouldBe ubyte
              }

              shouldNotRaise {
                fUShort.decodeValue(uShortSlice, Struct1(ubyte), testStruct)
              }.also { (decoded, remaining) ->
                remaining.firstIndex shouldBe uShortSlice.firstIndex + 2U
                remaining.lastIndex shouldBe uShortSlice.lastIndex

                decoded shouldBe ushort
              }
            }
          }

          should("raise an error if the decoded value is not equal to the constant") {
            checkAll(
              Arb.pair(Arb.uInt8(), Arb.uInt8()).filter { it.first != it.second }.flatMap { (ubyte, wrongUByte) ->
                Arb.slice(wrongUByte.encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { Triple(it, ubyte, wrongUByte) }
              },
              Arb.pair(Arb.uShort(), Arb.uShort()).filter { it.first != it.second }.flatMap { (ushort, wrongUShort) ->
                Arb.slice(uint16(wrongUShort).encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { Triple(it, ushort, wrongUShort) }
              },
            ) { (uByteSlice, ubyte, wrongUByte), (uShortSlice, ushort, wrongUShort) ->
              val fUInt8 = "uint8".ofType(uint8, 0U, checkedType = UInt8::class, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, checkedType = UShort::class, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldRaise<DecoderError.InvalidFieldValue> {
                fUInt8.decodeValue(uByteSlice, null, testStruct)
              } shouldBe DecoderError.InvalidFieldValue(uByteSlice.firstIndex, testStruct.name, 0U, ubyte, wrongUByte)

              shouldRaise<DecoderError.InvalidFieldValue> {
                fUShort.decodeValue(uShortSlice, Struct1(ubyte), testStruct)
              } shouldBe DecoderError.InvalidFieldValue(uShortSlice.firstIndex, testStruct.name, 1U, ushort, wrongUShort)
            }
          }
        }
      }

      context("without a checked type") {
        context(".encodeValue(value, _, structT)") {
          should("encode the value if it is equal to the constant") {
            checkAll(Arb.uInt8(), Arb.uShort()) { ubyte, ushort ->
              val fUInt8 = "uint8".ofType(uint8, 0U, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldNotRaise {
                fUInt8.encodeValue(ubyte, Struct2(ubyte, ushort), testStruct)
              } shouldBe ubyte.encode()

              shouldNotRaise {
                fUShort.encodeValue(ushort, Struct2(ubyte, ushort), testStruct)
              } shouldBe uint16(ushort).encode()
            }
          }

          should("raise an error if the value is different from the constant") {
            checkAll(
              Arb.pair(Arb.uInt8(), Arb.uInt8()).filter { it.first != it.second },
              Arb.pair(Arb.uShort(), Arb.uShort()).filter { it.first != it.second },
            ) { (ubyte, wrongUByte), (ushort, wrongUShort) ->
              val fUInt8 = "uint8".ofType(uint8, 0U, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldRaise<EncoderError.InvalidFieldValue> {
                (fUInt8 as Field<Any?>).encodeValue(wrongUByte, Struct2(wrongUByte, ushort), testStruct)
              } shouldBe EncoderError.InvalidFieldValue(testStruct.name, 0U, ubyte, wrongUByte)

              shouldRaise<EncoderError.InvalidFieldValue> {
                (fUShort as Field<Any?>).encodeValue(wrongUShort, Struct2(ubyte, wrongUShort), testStruct)
              } shouldBe EncoderError.InvalidFieldValue(testStruct.name, 1U, ushort, wrongUShort)
            }
          }
        }

        context(".decodeValue(bytes, _, structT") {
          should("decode the value if it is equal to the constant") {
            checkAll(
              Arb.uInt8().flatMap { ubyte ->
                Arb.slice(ubyte.encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { it to ubyte }
              },
              Arb.uShort().flatMap { ushort ->
                Arb.slice(uint16(ushort).encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { it to ushort }
              },
            ) { (uByteSlice, ubyte), (uShortSlice, ushort) ->
              val fUInt8 = "uint8".ofType(uint8, 0U, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldNotRaise {
                fUInt8.decodeValue(uByteSlice, null, testStruct)
              }.also { (decoded, remaining) ->
                remaining.firstIndex shouldBe uByteSlice.firstIndex + 1U
                remaining.lastIndex shouldBe uByteSlice.lastIndex

                decoded shouldBe ubyte
              }

              shouldNotRaise {
                fUShort.decodeValue(uShortSlice, Struct1(ubyte), testStruct)
              }.also { (decoded, remaining) ->
                remaining.firstIndex shouldBe uShortSlice.firstIndex + 2U
                remaining.lastIndex shouldBe uShortSlice.lastIndex

                decoded shouldBe ushort
              }
            }
          }

          should("raise an error if the decoded value is not equal to the constant") {
            checkAll(
              Arb.pair(Arb.uInt8(), Arb.uInt8()).filter { it.first != it.second }.flatMap { (ubyte, wrongUByte) ->
                Arb.slice(wrongUByte.encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { Triple(it, ubyte, wrongUByte) }
              },
              Arb.pair(Arb.uShort(), Arb.uShort()).filter { it.first != it.second }.flatMap { (ushort, wrongUShort) ->
                Arb.slice(uint16(wrongUShort).encode(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)
                  .map { Triple(it, ushort, wrongUShort) }
              },
            ) { (uByteSlice, ubyte, wrongUByte), (uShortSlice, ushort, wrongUShort) ->
              val fUInt8 = "uint8".ofType(uint8, 0U, constant = ubyte.some())
              val fUShort = "uShort".ofType(uint16.asUShort, 1U, constant = ushort.some())

              val testStruct =
                struct("Test") {
                  it.field("uint8", uint8, ubyte)
                    .field("uShort", uint16.asUShort, ushort)
                }

              shouldRaise<DecoderError.InvalidFieldValue> {
                fUInt8.decodeValue(uByteSlice, null, testStruct)
              } shouldBe DecoderError.InvalidFieldValue(uByteSlice.firstIndex, testStruct.name, 0U, ubyte, wrongUByte)

              shouldRaise<DecoderError.InvalidFieldValue> {
                fUShort.decodeValue(uShortSlice, Struct1(ubyte), testStruct)
              } shouldBe DecoderError.InvalidFieldValue(uShortSlice.firstIndex, testStruct.name, 1U, ushort, wrongUShort)
            }
          }
        }
      }
    }
  }
})
