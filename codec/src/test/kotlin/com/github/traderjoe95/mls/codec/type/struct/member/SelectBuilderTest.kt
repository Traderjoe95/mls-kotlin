package com.github.traderjoe95.mls.codec.type.struct.member

import arrow.core.toNonEmptyListOrNull
import com.github.traderjoe95.mls.codec.partition
import com.github.traderjoe95.mls.codec.subset
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.struct.Struct0T
import io.kotest.assertions.arrow.core.shouldBeNone
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.kotest.property.Arb
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.alphanumeric
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.of
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class SelectBuilderTest : ShouldSpec({
  context("SelectBuilder<V, E>") {
    context("if V : Any") {
      context("case(branch...).then(type, label)") {
        should("put a new field with the correct parameters and without a label to the cases map if label is null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
          ) { condition, index ->
            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .case(Version.V2).then(VariantField.V2Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V2Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                }
              }

            SelectBuilder<VariantField, _>(
              condition,
              Version.T,
              index,
            ).case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T).also {
              it.condition shouldBe condition
              it.conditionType shouldBe Version.T
              it.index shouldBe index

              it.cases.keys shouldBe setOf(Version.V3, Version.V4)
              it.cases[Version.V3].shouldNotBeNull().also { field ->
                field.name.shouldBeNull()
                field.type shouldBe VariantField.V3AndV4Variant.T
                field.index shouldBe index
                field.constant.shouldBeNone()
                field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
              }
              it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
            }
          }
        }

        should("put a new field with the correct parameters and with a label to the cases map if label is not null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.string(1..32, Codepoint.alphanumeric()),
          ) { condition, index, label ->
            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .case(Version.V2).then(VariantField.V2Variant.T, label)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name shouldBe label
                  field.type shouldBe VariantField.V2Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                }
              }

            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T, label).also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name shouldBe label
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
                it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
              }
          }
        }

        should("override the case if it already exists") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
          ) { condition, index ->
            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .case(Version.V2).then(VariantField.V2Variant.T)
              .case(Version.V2).then(VariantField.V3AndV4Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
              }

            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .case(Version.V3).then(VariantField.V2Variant.T)
              .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
                it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
              }

            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T)
              .case(Version.V3).then(VariantField.V2Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V2Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                }
                it.cases[Version.V4].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
              }
          }
        }
      }

      context("case(branches...).or(branch)") {
        should("return the same as case(branches..., branch)") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.pair(
              Arb.subset(Version.entries.filter(ProtocolEnum<*>::isValid).toSet()).filter(Set<Version>::isNotEmpty).map {
                it.toNonEmptyListOrNull() ?: error("unreachable")
              },
              Arb.of(Version.entries.filter(ProtocolEnum<*>::isValid)),
            ),
          ) { condition, index, (branches, singleBranch) ->
            val builder = SelectBuilder<VariantField, _>(condition, Version.T, index)
            val case1 =
              builder.case(branches.head, *branches.tail.toTypedArray()).or(singleBranch)
            val case2 =
              builder.case(branches.head, *branches.tail.toTypedArray(), singleBranch)

            case1.parent shouldBeSameInstanceAs case2.parent
            case1.values shouldBe case2.values
          }
        }
      }

      context("orElse(type, label)") {
        should("put new fields for all valid branches that aren't handled already without a label if label is null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.partition(Version.entries.filter(ProtocolEnum<*>::isValid).toSet()),
          ) { condition, index, (handled, unhandled) ->
            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .let {
                handled.toNonEmptyListOrNull()?.let { nel ->
                  it.case(nel.head, *nel.tail.toTypedArray()).then(VariantField.V2Variant.T)
                } ?: it
              }
              .orElse(VariantField.V3AndV4Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe Version.entries.filter(ProtocolEnum<*>::isValid).toSet()

                handled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe VariantField.V2Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                  }
                }

                unhandled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe VariantField.V3AndV4Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                  }
                }
              }
          }
        }

        should("put new fields for all valid branches that aren't handled already with a label if label is not null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.string(1..32, Codepoint.alphanumeric()),
            Arb.partition(Version.entries.filter(ProtocolEnum<*>::isValid).toSet()),
          ) { condition, index, label, (handled, unhandled) ->
            SelectBuilder<VariantField, _>(condition, Version.T, index)
              .let {
                handled.toNonEmptyListOrNull()?.let { nel ->
                  it.case(nel.head, *nel.tail.toTypedArray()).then(VariantField.V2Variant.T)
                } ?: it
              }
              .orElse(VariantField.V3AndV4Variant.T, label)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe Version.entries.filter(ProtocolEnum<*>::isValid).toSet()

                handled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe VariantField.V2Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                  }
                }

                unhandled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name shouldBe label
                    field.type shouldBe VariantField.V3AndV4Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                  }
                }
              }
          }
        }
      }
    }

    context("if V is nullable") {
      context("case(branch...).then(type, label)") {
        should("put a new field with the correct parameters and without a label to the cases map if label is null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
          ) { condition, index ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index).case(Version.V2).then(VariantField.V2Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V2Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                }
              }

            SelectBuilder<VariantField?, _>(
              condition,
              Version.T,
              index,
            ).case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T).also {
              it.condition shouldBe condition
              it.conditionType shouldBe Version.T
              it.index shouldBe index

              it.cases.keys shouldBe setOf(Version.V3, Version.V4)
              it.cases[Version.V3].shouldNotBeNull().also { field ->
                field.name.shouldBeNull()
                field.type shouldBe VariantField.V3AndV4Variant.T
                field.index shouldBe index
                field.constant.shouldBeNone()
                field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
              }
              it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
            }
          }
        }

        should("put a new field with the correct parameters and with a label to the cases map if label is not null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.string(1..32, Codepoint.alphanumeric()),
          ) { condition, index, label ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V2).then(VariantField.V2Variant.T, label)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name shouldBe label
                  field.type shouldBe VariantField.V2Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                }
              }

            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T, label).also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name shouldBe label
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
                it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
              }
          }
        }

        should("override the case if it already exists") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
          ) { condition, index ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V2).then(VariantField.V2Variant.T)
              .case(Version.V2).then(VariantField.V3AndV4Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
              }

            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V3).then(VariantField.V2Variant.T)
              .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
                it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
              }

            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T)
              .case(Version.V3).then(VariantField.V2Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V2Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                }
                it.cases[Version.V4].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
              }
          }
        }
      }

      context("case(branch...).thenNothing()") {
        should("put a new Struct0T field with the correct parameters") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
          ) { condition, index ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V2).thenNothing()
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe Struct0T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldBeNull()
                }
              }

            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V3, Version.V4).thenNothing().also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe Struct0T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldBeNull()
                }
                it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
              }
          }
        }

        should("override the case if it already exists") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
          ) { condition, index ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V2).then(VariantField.V2Variant.T)
              .case(Version.V2).thenNothing()
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V2)
                it.cases[Version.V2].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe Struct0T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldBeNull()
                }
              }

            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V3).then(VariantField.V3AndV4Variant.T)
              .case(Version.V3, Version.V4).thenNothing()
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe Struct0T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldBeNull()
                }
                it.cases[Version.V4] shouldBeSameInstanceAs it.cases[Version.V3]
              }

            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .case(Version.V3, Version.V4).then(VariantField.V3AndV4Variant.T)
              .case(Version.V3).thenNothing()
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe setOf(Version.V3, Version.V4)
                it.cases[Version.V3].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe Struct0T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldBeNull()
                }
                it.cases[Version.V4].shouldNotBeNull().also { field ->
                  field.name.shouldBeNull()
                  field.type shouldBe VariantField.V3AndV4Variant.T
                  field.index shouldBe index
                  field.constant.shouldBeNone()
                  field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                }
              }
          }
        }
      }

      context("case(branches...).or(branch)") {
        should("return the same as case(branches..., branch)") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.pair(
              Arb.subset(Version.entries.filter(ProtocolEnum<*>::isValid).toSet()).filter(Set<Version>::isNotEmpty).map {
                it.toNonEmptyListOrNull() ?: error("unreachable")
              },
              Arb.of(Version.entries.filter(ProtocolEnum<*>::isValid)),
            ),
          ) { condition, index, (branches, singleBranch) ->
            val builder = SelectBuilder<VariantField?, _>(condition, Version.T, index)
            val case1 =
              builder.case(branches.head, *branches.tail.toTypedArray()).or(singleBranch)
            val case2 =
              builder.case(branches.head, *branches.tail.toTypedArray(), singleBranch)

            case1.parent shouldBeSameInstanceAs case2.parent
            case1.values shouldBe case2.values
          }
        }
      }

      context("orElse(type, label)") {
        should("put new fields for all valid branches that aren't handled already without a label if label is null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.partition(Version.entries.filter(ProtocolEnum<*>::isValid).toSet()),
          ) { condition, index, (handled, unhandled) ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .let {
                handled.toNonEmptyListOrNull()?.let { nel ->
                  it.case(nel.head, *nel.tail.toTypedArray()).then(VariantField.V2Variant.T)
                } ?: it
              }
              .orElse(VariantField.V3AndV4Variant.T)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe Version.entries.filter(ProtocolEnum<*>::isValid).toSet()

                handled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe VariantField.V2Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                  }
                }

                unhandled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe VariantField.V3AndV4Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                  }
                }
              }
          }
        }

        should("put new fields for all valid branches that aren't handled already with a label if label is not null") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.string(1..32, Codepoint.alphanumeric()),
            Arb.partition(Version.entries.filter(ProtocolEnum<*>::isValid).toSet()),
          ) { condition, index, label, (handled, unhandled) ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .let {
                handled.toNonEmptyListOrNull()?.let { nel ->
                  it.case(nel.head, *nel.tail.toTypedArray()).then(VariantField.V2Variant.T)
                } ?: it
              }
              .orElse(VariantField.V3AndV4Variant.T, label)
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe Version.entries.filter(ProtocolEnum<*>::isValid).toSet()

                handled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe VariantField.V2Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                  }
                }

                unhandled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name shouldBe label
                    field.type shouldBe VariantField.V3AndV4Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V3AndV4Variant::class)
                  }
                }
              }
          }
        }
      }

      context("orElseNothing") {
        should("put a new Struct0T field with the correct parameters for all valid branches that aren't handled already") {
          checkAll(
            Arb.list(Arb.string(1..32, Codepoint.alphanumeric()), 1..5).map {
              it.toNonEmptyListOrNull() ?: error("unreachable")
            },
            Arb.uInt(),
            Arb.partition(Version.entries.filter(ProtocolEnum<*>::isValid).toSet()),
          ) { condition, index, (handled, unhandled) ->
            SelectBuilder<VariantField?, _>(condition, Version.T, index)
              .let {
                handled.toNonEmptyListOrNull()?.let { nel ->
                  it.case(nel.head, *nel.tail.toTypedArray()).then(VariantField.V2Variant.T)
                } ?: it
              }
              .orElseNothing()
              .also {
                it.condition shouldBe condition
                it.conditionType shouldBe Version.T
                it.index shouldBe index

                it.cases.keys shouldBe Version.entries.filter(ProtocolEnum<*>::isValid).toSet()

                handled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe VariantField.V2Variant.T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldNotBeNull().shouldBeEqual(VariantField.V2Variant::class)
                  }
                }

                unhandled.forEach { version ->
                  it.cases[version].shouldNotBeNull().also { field ->
                    field.name.shouldBeNull()
                    field.type shouldBe Struct0T
                    field.index shouldBe index
                    field.constant.shouldBeNone()
                    field.checkedType.shouldBeNull()
                  }
                }
              }
          }
        }
      }
    }
  }
})
