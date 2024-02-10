package com.github.traderjoe95.mls.codec.type.struct.member

import arrow.core.nonEmptyListOf
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.SelectError
import com.github.traderjoe95.mls.codec.partition
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.struct.Struct0T
import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.type.uint64
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.util.toBytes
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.alphanumeric
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.uByte
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class SelectTest : ShouldSpec({
  context("Select<V, E>") {
    context(".check(structT)") {
      val enumStruct =
        struct("WithEnum") {
          it.field("theEnum", Version.T)
            .field("notEnum", uint8)
        }

      val nestedStruct1Level =
        struct("Nested1Lvl") {
          it.field("nested", enumStruct)
            .field("notStruct", uint16)
        }

      val nestedStruct2Levels =
        struct("Nested2Lvl") {
          it.field("level1", nestedStruct1Level)
            .field("notStruct", uint32)
        }

      context("when structT has the condition field") {
        context("and the field is of the correct type") {
          should("succeed if all cases of the enum are handled") {
            shouldNotRaise {
              Select(nonEmptyListOf("theEnum"), Version.T, Version.all, 2U, enumStruct).check()
            }

            shouldNotRaise {
              Select(nonEmptyListOf("nested", "theEnum"), Version.T, Version.all, 2U, nestedStruct1Level).check()
            }

            shouldNotRaise {
              Select(
                nonEmptyListOf("level1", "nested", "theEnum"),
                Version.T,
                Version.all,
                2U,
                nestedStruct2Levels,
              ).check()
            }
          }

          should("succeed only the valid cases of the enum are handled") {
            shouldNotRaise {
              Select(nonEmptyListOf("theEnum"), Version.T, Version.onlyValid, 2U, enumStruct).check()
            }

            shouldNotRaise {
              Select(nonEmptyListOf("nested", "theEnum"), Version.T, Version.onlyValid, 2U, nestedStruct1Level).check()
            }

            shouldNotRaise {
              Select(
                nonEmptyListOf("level1", "nested", "theEnum"),
                Version.T,
                Version.onlyValid,
                2U,
                nestedStruct2Levels,
              ).check()
            }
          }

          should("raise an error if at least one valid case of the enum is unhandled") {
            checkAll(
              Arb.partition(Version.onlyValid.keys).filter { it.second.isNotEmpty() },
            ) { (handled, unhandled) ->
              val cases = handled.associateWith { Field(null, Struct0T, 2U) }
              val missing = unhandled.map(ProtocolEnum<*>::name).toSet()

              shouldRaise<SelectError.UnhandledSelectBranches> {
                Select(nonEmptyListOf("theEnum"), Version.T, cases, 2U, enumStruct).check()
              } shouldBe SelectError.UnhandledSelectBranches("WithEnum", "Version", missing)

              shouldRaise<SelectError.UnhandledSelectBranches> {
                Select(nonEmptyListOf("nested", "theEnum"), Version.T, cases, 2U, nestedStruct1Level).check()
              } shouldBe SelectError.UnhandledSelectBranches("Nested1Lvl", "Version", missing)

              shouldRaise<SelectError.UnhandledSelectBranches> {
                Select(
                  nonEmptyListOf("level1", "nested", "theEnum"),
                  Version.T,
                  cases,
                  2U,
                  nestedStruct2Levels,
                ).check()
              } shouldBe SelectError.UnhandledSelectBranches("Nested2Lvl", "Version", missing)
            }
          }
        }

        should("raise an error if the field is of a wrong type") {
          shouldRaise<SelectError.ExpectedEnum> {
            Select(nonEmptyListOf("notEnum"), Version.T, Version.onlyValid, 2U, enumStruct).check()
          } shouldBe SelectError.ExpectedEnum("WithEnum", "notEnum", "Version", "uint8")

          shouldRaise<SelectError.ExpectedEnum> {
            Select(nonEmptyListOf("nested", "notEnum"), Version.T, Version.onlyValid, 2U, nestedStruct1Level).check()
          } shouldBe SelectError.ExpectedEnum("WithEnum", "notEnum", "Version", "uint8")

          shouldRaise<SelectError.ExpectedEnum> {
            Select(
              nonEmptyListOf("level1", "nested", "notEnum"),
              Version.T,
              Version.onlyValid,
              2U,
              nestedStruct2Levels,
            ).check()
          } shouldBe SelectError.ExpectedEnum("WithEnum", "notEnum", "Version", "uint8")
        }
      }

      should("raise an error if the field is unknown") {
        shouldRaise<SelectError.UnknownField> {
          Select(nonEmptyListOf("unknown"), Version.T, Version.onlyValid, 2U, enumStruct).check()
        } shouldBe SelectError.UnknownField("WithEnum", "unknown")

        shouldRaise<SelectError.UnknownField> {
          Select(nonEmptyListOf("nested", "unknown"), Version.T, Version.onlyValid, 2U, nestedStruct1Level).check()
        } shouldBe SelectError.UnknownField("WithEnum", "unknown")

        shouldRaise<SelectError.UnknownField> {
          Select(
            nonEmptyListOf("level1", "nested", "unknown"),
            Version.T,
            Version.onlyValid,
            2U,
            nestedStruct2Levels,
          ).check()
        } shouldBe SelectError.UnknownField("WithEnum", "unknown")
      }

      should("raise an error if any field on the nesting path is unknown") {
        checkAll(Arb.string(1..32, Codepoint.alphanumeric())) { field ->
          shouldRaise<SelectError.UnknownField> {
            Select(nonEmptyListOf(field, "theEnum"), Version.T, Version.onlyValid, 2U, nestedStruct1Level).check()
          } shouldBe SelectError.UnknownField("Nested1Lvl", field)

          shouldRaise<SelectError.UnknownField> {
            Select(
              nonEmptyListOf("level1", field, "theEnum"),
              Version.T,
              Version.onlyValid,
              2U,
              nestedStruct2Levels,
            ).check()
          } shouldBe SelectError.UnknownField("Nested1Lvl", field)

          shouldRaise<SelectError.UnknownField> {
            Select(
              nonEmptyListOf(field, "nested", "theEnum"),
              Version.T,
              Version.onlyValid,
              2U,
              nestedStruct2Levels,
            ).check()
          } shouldBe SelectError.UnknownField("Nested2Lvl", field)
        }
      }

      should("raise an error if any field on the nesting path is not a struct") {
        shouldRaise<SelectError.ExpectedStruct> {
          Select(nonEmptyListOf("notStruct", "theEnum"), Version.T, Version.onlyValid, 2U, nestedStruct1Level).check()
        } shouldBe SelectError.ExpectedStruct("Nested1Lvl", "notStruct", "uint16")

        shouldRaise<SelectError.ExpectedStruct> {
          Select(
            nonEmptyListOf("level1", "notStruct", "theEnum"),
            Version.T,
            Version.onlyValid,
            2U,
            nestedStruct2Levels,
          ).check()
        } shouldBe SelectError.ExpectedStruct("Nested1Lvl", "notStruct", "uint16")

        shouldRaise<SelectError.ExpectedStruct> {
          Select(
            nonEmptyListOf("notStruct", "nested", "theEnum"),
            Version.T,
            Version.onlyValid,
            2U,
            nestedStruct2Levels,
          ).check()
        } shouldBe SelectError.ExpectedStruct("Nested2Lvl", "notStruct", "uint32")
      }
    }

    context(".encodeValue(value, struct, structT)") {
      val variantStruct =
        struct("Variants") { b ->
          b.field("version", Version.T)
            .select<VariantField?, _>(Version.T, "version") {
              case(Version.V2).then(VariantField.V2Variant.T)
                .case(Version.V3).or(Version.V4).then(VariantField.V3AndV4Variant.T)
                .orElseNothing()
            }
        }

      val nestedVariantStruct =
        struct("VariantsNested") { b ->
          b.field("nested", struct("Nested") { it.field("version", Version.T) })
            .select<VariantField?, _>(Version.T, "nested", "version") {
              case(Version.V2).then(VariantField.V2Variant.T)
                .case(Version.V3).or(Version.V4).then(VariantField.V3AndV4Variant.T)
                .orElseNothing()
            }
        }

      should("encode the correct value based on the enum branch") {
        shouldNotRaise {
          variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
            null,
            Struct2(Version.V1, null),
            variantStruct,
          )
        } shouldBe byteArrayOf()

        shouldNotRaise {
          nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
            null,
            Struct2(Struct1(Version.V1), null),
            nestedVariantStruct,
          )
        } shouldBe byteArrayOf()

        checkAll(Arb.uByte(), Arb.uInt()) { ubyte, uint ->
          shouldNotRaise {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Version.V2, VariantField.V2Variant(ubyte)),
              variantStruct,
            )
          } shouldBe byteArrayOf(ubyte.toByte())

          shouldNotRaise {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Struct1(Version.V2), VariantField.V2Variant(ubyte)),
              nestedVariantStruct,
            )
          } shouldBe byteArrayOf(ubyte.toByte())

          shouldNotRaise {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(Version.V3, VariantField.V3AndV4Variant(ubyte, uint)),
              variantStruct,
            )
          } shouldBe byteArrayOf(ubyte.toByte(), *uint.toBytes(4U))

          shouldNotRaise {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(Struct1(Version.V3), VariantField.V3AndV4Variant(ubyte, uint)),
              nestedVariantStruct,
            )
          } shouldBe byteArrayOf(ubyte.toByte(), *uint.toBytes(4U))

          shouldNotRaise {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(Version.V4, VariantField.V3AndV4Variant(ubyte, uint)),
              variantStruct,
            )
          } shouldBe byteArrayOf(ubyte.toByte(), *uint.toBytes(4U))

          shouldNotRaise {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(Struct1(Version.V4), VariantField.V3AndV4Variant(ubyte, uint)),
              nestedVariantStruct,
            )
          } shouldBe byteArrayOf(ubyte.toByte(), *uint.toBytes(4U))
        }
      }

      should("raise an error if the wrong variant is used") {
        checkAll(Arb.uByte(), Arb.uInt()) { ubyte, uint ->
          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Version.V1, VariantField.V2Variant(ubyte)),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "null (= struct {})",
              VariantField.V2Variant(ubyte),
            )

          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(Version.V1, VariantField.V3AndV4Variant(ubyte, uint)),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "null (= struct {})",
              VariantField.V3AndV4Variant(ubyte, uint),
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Struct1(Version.V1), VariantField.V2Variant(ubyte)),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "null (= struct {})",
              VariantField.V2Variant(ubyte),
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(
                Struct1(Version.V1),
                VariantField.V3AndV4Variant(ubyte, uint),
              ),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "null (= struct {})",
              VariantField.V3AndV4Variant(ubyte, uint),
            )

          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              null,
              Struct2(Version.V2, null),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "V2Variant",
              null,
            )

          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(Version.V2, VariantField.V3AndV4Variant(ubyte, uint)),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "V2Variant",
              VariantField.V3AndV4Variant(ubyte, uint),
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              null,
              Struct2(Struct1(Version.V2), null),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "V2Variant",
              null,
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V3AndV4Variant(ubyte, uint),
              Struct2(Struct1(Version.V2), VariantField.V3AndV4Variant(ubyte, uint)),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "V2Variant",
              VariantField.V3AndV4Variant(ubyte, uint),
            )

          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              null,
              Struct2(Version.V3, null),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "V3AndV4Variant",
              null,
            )

          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Version.V3, VariantField.V2Variant(ubyte)),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "V3AndV4Variant",
              VariantField.V2Variant(ubyte),
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              null,
              Struct2(Struct1(Version.V3), null),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "V3AndV4Variant",
              null,
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Struct1(Version.V3), VariantField.V2Variant(ubyte)),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "V3AndV4Variant",
              VariantField.V2Variant(ubyte),
            )

          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              null,
              Struct2(Version.V4, null),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "V3AndV4Variant",
              null,
            )

          shouldRaise<EncoderError.WrongVariant> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Version.V4, VariantField.V2Variant(ubyte)),
              variantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "Variants",
              1U,
              "V3AndV4Variant",
              VariantField.V2Variant(ubyte),
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              null,
              Struct2(Struct1(Version.V4), null),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "V3AndV4Variant",
              null,
            )

          shouldRaise<EncoderError.WrongVariant> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().encodeValue(
              VariantField.V2Variant(ubyte),
              Struct2(Struct1(Version.V4), VariantField.V2Variant(ubyte)),
              nestedVariantStruct,
            )
          } shouldBe
            EncoderError.WrongVariant(
              "VariantsNested",
              1U,
              "V3AndV4Variant",
              VariantField.V2Variant(ubyte),
            )
        }
      }
    }

    context(".decodeValue(bytes, alreadyDecoded, structT)") {
      val variantStruct =
        struct("Variants") { b ->
          b.field("version", Version.T)
            .select<VariantField?, _>(Version.T, "version") {
              case(Version.V2).then(VariantField.V2Variant.T)
                .case(Version.V3).or(Version.V4).then(VariantField.V3AndV4Variant.T)
                .orElseNothing()
            }
        }

      val nestedVariantStruct =
        struct("VariantsNested") { b ->
          b.field("nested", struct("Nested") { it.field("version", Version.T) })
            .select<VariantField?, _>(Version.T, "nested", "version") {
              case(Version.V2).then(VariantField.V2Variant.T)
                .case(Version.V3).or(Version.V4).then(VariantField.V3AndV4Variant.T)
                .orElseNothing()
            }
        }

      should("not consume any bytes and return null if the variant has Struct0T") {
        checkAll(Arb.slice(byteArrayOf(), alreadyConsumedLength = 0U..128U, extraLength = 0U..128U)) { bytes ->
          shouldNotRaise {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Version.V1),
              variantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded.shouldBeNull()

            remaining.firstIndex shouldBe bytes.firstIndex
            remaining.lastIndex shouldBe bytes.lastIndex
          }

          shouldNotRaise {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Struct1(Version.V1)),
              nestedVariantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded.shouldBeNull()

            remaining.firstIndex shouldBe bytes.firstIndex
            remaining.lastIndex shouldBe bytes.lastIndex
          }
        }
      }

      should("decode the correct variant value if the type is not Struct0T") {
        checkAll(
          Arb.pair(Arb.uByte(), Arb.uInt()).flatMap { (ubyte, uint) ->
            Arb.slice(
              byteArrayOf(ubyte.toByte(), *uint.toBytes(4U)),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { Triple(it, ubyte, uint) }
          },
        ) { (bytes, ubyte, uint) ->
          shouldNotRaise {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Version.V2),
              variantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded shouldBe VariantField.V2Variant(ubyte)

            remaining.firstIndex shouldBe bytes.firstIndex + 1U
            remaining.lastIndex shouldBe bytes.lastIndex
          }

          shouldNotRaise {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Struct1(Version.V2)),
              nestedVariantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded shouldBe VariantField.V2Variant(ubyte)

            remaining.firstIndex shouldBe bytes.firstIndex + 1U
            remaining.lastIndex shouldBe bytes.lastIndex
          }

          shouldNotRaise {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Version.V3),
              variantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded shouldBe VariantField.V3AndV4Variant(ubyte, uint)

            remaining.firstIndex shouldBe bytes.firstIndex + 5U
            remaining.lastIndex shouldBe bytes.lastIndex
          }

          shouldNotRaise {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Struct1(Version.V3)),
              nestedVariantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded shouldBe VariantField.V3AndV4Variant(ubyte, uint)

            remaining.firstIndex shouldBe bytes.firstIndex + 5U
            remaining.lastIndex shouldBe bytes.lastIndex
          }

          shouldNotRaise {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Version.V4),
              variantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded shouldBe VariantField.V3AndV4Variant(ubyte, uint)

            remaining.firstIndex shouldBe bytes.firstIndex + 5U
            remaining.lastIndex shouldBe bytes.lastIndex
          }

          shouldNotRaise {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Struct1(Version.V4)),
              nestedVariantStruct,
            )
          }.also { (decoded, remaining) ->
            decoded shouldBe VariantField.V3AndV4Variant(ubyte, uint)

            remaining.firstIndex shouldBe bytes.firstIndex + 5U
            remaining.lastIndex shouldBe bytes.lastIndex
          }
        }
      }

      should("raise an error if there aren't enough bytes for the selected variant") {
        checkAll(Arb.slice(byteArrayOf(), alreadyConsumedLength = 0U..128U)) { bytes ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Version.V2),
              variantStruct,
            )
          } shouldBe DecoderError.PrematureEndOfStream(bytes.firstIndex, 1U, 0U)

          shouldRaise<DecoderError.PrematureEndOfStream> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Struct1(Version.V2)),
              nestedVariantStruct,
            )
          } shouldBe DecoderError.PrematureEndOfStream(bytes.firstIndex, 1U, 0U)
        }

        checkAll(Arb.slice(Arb.byteArray(0..4), alreadyConsumedLength = 0U..128U)) { bytes ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Version.V3),
              variantStruct,
            )
          } shouldBe
            DecoderError.PrematureEndOfStream(
              if (bytes.size > 0U) bytes.firstIndex + 1U else bytes.firstIndex,
              if (bytes.size > 0U) 4U else 1U,
              if (bytes.size > 0U) bytes.size - 1U else 0U,
            )

          shouldRaise<DecoderError.PrematureEndOfStream> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Struct1(Version.V3)),
              nestedVariantStruct,
            )
          } shouldBe
            DecoderError.PrematureEndOfStream(
              if (bytes.size > 0U) bytes.firstIndex + 1U else bytes.firstIndex,
              if (bytes.size > 0U) 4U else 1U,
              if (bytes.size > 0U) bytes.size - 1U else 0U,
            )

          shouldRaise<DecoderError.PrematureEndOfStream> {
            variantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Version.V4),
              variantStruct,
            )
          } shouldBe
            DecoderError.PrematureEndOfStream(
              if (bytes.size > 0U) bytes.firstIndex + 1U else bytes.firstIndex,
              if (bytes.size > 0U) 4U else 1U,
              if (bytes.size > 0U) bytes.size - 1U else 0U,
            )

          shouldRaise<DecoderError.PrematureEndOfStream> {
            nestedVariantStruct.members[1].shouldBeInstanceOf<Select<VariantField?, Version>>().decodeValue(
              bytes,
              Struct1(Struct1(Version.V4)),
              nestedVariantStruct,
            )
          } shouldBe
            DecoderError.PrematureEndOfStream(
              if (bytes.size > 0U) bytes.firstIndex + 1U else bytes.firstIndex,
              if (bytes.size > 0U) 4U else 1U,
              if (bytes.size > 0U) bytes.size - 1U else 0U,
            )
        }
      }
    }

    context(".encodedLength") {
      should("have a value if all variants have the same length") {
        val struct =
          shouldNotRaise {
            struct("SelectWithLength") {
              it.field("version", Version.T)
                .select<Any?, _>(Version.T, "version") {
                  case(Version.V1).then(uint8[8U], "uint8Vec")
                    .case(Version.V2).then(uint16[8U], "uint16Vec")
                    .case(Version.V3).then(uint32[8U], "uint32Vec")
                    .case(Version.V4).then(uint64, "uint64")
                    // Invalid cases should not count
                    .case(Version.Reserved).then(uint64[16U])
                    .case(Version.UPPER_).thenNothing()
                }
            }
          }

        struct.member2.shouldBeInstanceOf<Select<Any?, Version>>().encodedLength shouldBe 8U
      }
    }
  }
})

enum class Version(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<Version> {
  Reserved(0U, false),
  V1(1U),
  V2(2U),
  V3(3U),
  V4(4U),
  UPPER_(255U, false),
  ;

  override val ord: UIntRange = ord..ord

  companion object {
    val T: EnumT<Version> = throwAnyError { enum() }

    val all: Map<Version, Field<Nothing?>> =
      entries.associateWith { Field(null, Struct0T, 2U) }

    val onlyValid: Map<Version, Field<Nothing?>> =
      entries.filter { it.isValid }.associateWith { Field(null, Struct0T, 2U) }
  }
}

sealed interface VariantField {
  data class V2Variant(val field: UByte) : VariantField, Struct1T.Shape<UByte> {
    companion object {
      val T =
        struct("V2Variant") {
          it.field("field", uint8.asUByte)
        }.lift(VariantField::V2Variant)
    }
  }

  data class V3AndV4Variant(val field1: UByte, val field2: UInt) : VariantField, Struct2T.Shape<UByte, UInt> {
    companion object {
      val T =
        struct("V3AndV4Variant") {
          it.field("field1", uint8.asUByte)
            .field("field2", uint32.asUInt)
        }.lift(VariantField::V3AndV4Variant)
    }
  }
}
