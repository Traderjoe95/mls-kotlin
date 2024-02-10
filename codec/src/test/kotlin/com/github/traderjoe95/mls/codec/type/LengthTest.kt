package com.github.traderjoe95.mls.codec.type

import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.div
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.LengthError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.times
import com.github.traderjoe95.mls.codec.type.DataType.Companion.done
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.uIntRange
import com.github.traderjoe95.mls.codec.util.full
import com.github.traderjoe95.mls.codec.util.shrToByte
import com.github.traderjoe95.mls.codec.v1Byte
import com.github.traderjoe95.mls.codec.v2Bytes
import com.github.traderjoe95.mls.codec.v4Bytes
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll
import kotlin.experimental.or

class LengthTest : ShouldSpec({
  context("FixedLength") {
    should("always return an empty array when calling encode with the correct length") {
      checkAll(Arb.uInt()) {
        shouldNotRaise { FixedLength.of(it, uint8).encode(it) shouldBe byteArrayOf() }
      }
    }

    should("always return (length, slice) when calling decode on any slice") {
      checkAll(Arb.uInt(), Arb.slice(Arb.byteArray(0..1024))) { length, slice ->
        shouldNotRaise {
          FixedLength.of(length, uint8).decode(slice).also { (l, remaining) ->
            l shouldBe length
            remaining shouldBe slice
          }
        }
      }
    }

    should("raise an error if the length is not the fixed length") {
      checkAll(Arb.pair(Arb.uInt(), Arb.uInt()).filter { it.first != it.second }) { (fixed, length) ->
        shouldRaise<EncoderError.BadLength> { FixedLength.of(fixed, uint8).encode(length) }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of 0") {
        checkAll(Arb.uInt().filter { it % 2U == 0U }) {
          shouldNotRaise { FixedLength.of(it, uint8) }.encodedLength shouldBe 0U
          shouldNotRaise { FixedLength.of(it, uint16) }.encodedLength shouldBe 0U
        }
      }

      should("have a name of [fixed]") {
        checkAll(Arb.uInt().filter { it % 2U == 0U }) {
          shouldNotRaise { FixedLength.of(it, uint8) }.name shouldBe "[$it]"
          shouldNotRaise { FixedLength.of(it, uint16) }.name shouldBe "[$it]"
        }
      }
    }

    context(".of(length, dataType)") {
      should("return FixedLength(length) if the data type has a fixed size and the length is a multiple of the data type size") {
        checkAll(Arb.uInt(0U..1024U)) {
          shouldNotRaise { FixedLength.of(it, uint8).encode(it) }
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 2U == 0U }) {
          shouldNotRaise { FixedLength.of(it, uint16).encode(it) }
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 3U == 0U }) {
          shouldNotRaise { FixedLength.of(it, uint24).encode(it) }
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 4U == 0U }) {
          shouldNotRaise {
            FixedLength.of(it, uint32).encode(it)
            FixedLength.of(it, uint16[2U]).encode(it)
          }
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 8U == 0U }) {
          shouldNotRaise {
            FixedLength.of(it, uint64).encode(it)
          }
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 24U == 0U }) {
          shouldNotRaise {
            FixedLength.of(it, opaque[24U]).encode(it)
          }
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 10U == 0U }) {
          shouldNotRaise {
            FixedLength.of(
              it,
              struct("test") {
                it.field("short", uint16)
                  .field("long", uint64)
              },
            ).encode(it)
          }
        }
      }

      should("raise an error if dataType has no known size") {
        checkAll(Arb.uInt(0U..1024U)) {
          shouldRaise<LengthError.UndefinedLength> {
            FixedLength.of(it, uint8[V])
          }.also {
            it.lengthType shouldBe "fixed"
            it.dataType shouldBe "uint8<V>"
          }
          shouldRaise<LengthError.UndefinedLength> {
            FixedLength.of(it, uint8[10U..20U])
          }.also {
            it.lengthType shouldBe "fixed"
            it.dataType shouldBe "uint8<10..20>"
          }
        }
      }

      should("raise an error if the length is not a multiple of the data type size") {
        checkAll(Arb.uInt(0U..1024U).filter { it % 2U != 0U }) {
          shouldRaise<LengthError.BadLength> {
            FixedLength.of(it, uint16).encode(it)
          } shouldBe LengthError.BadLength(it, "uint16", 2U)
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 3U != 0U }) {
          shouldRaise<LengthError.BadLength> {
            FixedLength.of(it, uint24).encode(it)
          } shouldBe LengthError.BadLength(it, "uint24", 3U)
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 4U != 0U }) {
          shouldRaise<LengthError.BadLength> {
            FixedLength.of(it, uint32).encode(it)
          } shouldBe LengthError.BadLength(it, "uint32", 4U)
          shouldRaise<LengthError.BadLength> {
            FixedLength.of(it, uint16[4U]).encode(it)
          } shouldBe LengthError.BadLength(it, "uint16[4]", 4U)
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 8U != 0U }) {
          shouldRaise<LengthError.BadLength> {
            FixedLength.of(it, uint64).encode(it)
          } shouldBe LengthError.BadLength(it, "uint64", 8U)
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 24U != 0U }) {
          shouldRaise<LengthError.BadLength> {
            FixedLength.of(it, opaque[24U]).encode(it)
          } shouldBe LengthError.BadLength(it, "opaque[24]", 24U)
        }

        checkAll(Arb.uInt(0U..1024U).filter { it % 10U != 0U }) {
          shouldRaise<LengthError.BadLength> {
            FixedLength.of(
              it,
              struct("test") {
                it.field("short", uint16)
                  .field("long", uint64)
              },
            ).encode(it)
          } shouldBe LengthError.BadLength(it, "test", 10U)
        }
      }
    }
  }

  context("IntervalLength") {
    should("decode a length that it previously encoded") {
      checkAll(10, Arb.uIntRange(0U..1023U, 1U..1024U)) { interval ->
        val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

        checkAll(100, Arb.uInt(interval)) {
          shouldNotRaise { length.decode(length.encode(it).full).done() shouldBe it }
        }
      }
    }

    context("when encoding") {
      should("encode the length with a single byte if the upper bound of the interval is <= 0xFF") {
        checkAll(10, Arb.uIntRange(0U..254U, 1U..255U)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(100, Arb.uInt(interval)) {
            shouldNotRaise { length.encode(it) shouldBe byteArrayOf(it.toByte()) }
          }
        }
      }

      should("encode the length with two bytes if the upper bound of the interval is in 0x100..0xFFFF") {
        checkAll(10, Arb.uIntRange(0U..65534U, 256U..65535U)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(100, Arb.uInt(interval)) {
            shouldNotRaise {
              length.encode(it) shouldBe
                byteArrayOf(
                  it shrToByte 8,
                  it.toByte(),
                )
            }
          }
        }
      }

      should("encode the length with three bytes if the upper bound of the interval is in 0x1000000..0xFFFFFFFF") {
        checkAll(10, Arb.uIntRange(0U..(0xfffffffeU), 0x1000000U..0xffffffffU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(100, Arb.uInt(interval)) {
            shouldNotRaise {
              length.encode(it) shouldBe
                byteArrayOf(
                  it shrToByte 24,
                  it shrToByte 16,
                  it shrToByte 8,
                  it.toByte(),
                )
            }
          }
        }
      }

      should("encode the length with four bytes if the upper bound of the interval is in 0x10000..0xFFFFFF") {
        checkAll(10, Arb.uIntRange(0U..(0xfffffeU), 0x10000U..0xffffffU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(100, Arb.uInt(interval)) {
            shouldNotRaise {
              length.encode(it) shouldBe
                byteArrayOf(
                  it shrToByte 16,
                  it shrToByte 8,
                  it.toByte(),
                )
            }
          }
        }
      }

      should("raise an error if the length is not in the interval") {
        checkAll(10, Arb.uIntRange(1U..(0xfffffdU), 2U..0xfffffeU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.choice(
              Arb.uInt(0U..<interval.first),
              Arb.uInt((interval.last + 1U)..0xfffffffeU),
            ),
          ) {
            shouldRaise<EncoderError.BadLength> { length.encode(it) }
          }
        }
      }

      should("raise an error if the length is not a multiple of the data type width") {
        checkAll(
          10,
          Arb.uIntRange(0U..(0x7fffffffU), 0x80000000U..0xffffffffU).filter {
            it.first % 2U == 0U && it.last % 2U == 0U
          },
        ) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint16) }

          checkAll(
            100,
            Arb.uInt(interval).filter { it % 2U == 1U },
          ) {
            shouldRaise<EncoderError.BadLength> { length.encode(it) }
          }
        }
      }
    }

    context("when decoding") {
      should("consume one byte, decoding it as the length, if it is in the interval and the upper bound is <= 0xFF") {
        checkAll(10, Arb.uIntRange(0U..254U, 1U..255U)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.uInt(interval).flatMap { l ->
              Arb.slice(
                byteArrayOf(l.toByte()),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldNotRaise {
              length.decode(slice).also { (decoded, remaining) ->
                remaining.size shouldBe slice.size - 1U
                remaining.firstIndex shouldBe slice.firstIndex + 1U
                remaining.lastIndex shouldBe slice.lastIndex

                decoded shouldBe l
              }
            }
          }
        }
      }

      should("consume two bytes, decoding them as the length, if it is in the interval and the upper bound is in 0x100..0xFFFF") {
        checkAll(10, Arb.uIntRange(0U..65534U, 256U..65535U)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.uInt(interval).flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldNotRaise {
              length.decode(slice).also { (decoded, remaining) ->
                remaining.size shouldBe slice.size - 2U
                remaining.firstIndex shouldBe slice.firstIndex + 2U
                remaining.lastIndex shouldBe slice.lastIndex

                decoded shouldBe l
              }
            }
          }
        }
      }

      should("consume three bytes, decoding them as the length, if it is in the interval and the upper bound is in 0x10000..0xFFFFFF") {
        checkAll(10, Arb.uIntRange(0U..(0xfffffeU), 0x10000U..0xffffffU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.uInt(interval).flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 16,
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldNotRaise {
              length.decode(slice).also { (decoded, remaining) ->
                remaining.size shouldBe slice.size - 3U
                remaining.firstIndex shouldBe slice.firstIndex + 3U
                remaining.lastIndex shouldBe slice.lastIndex

                decoded shouldBe l
              }
            }
          }
        }
      }

      should("consume four bytes, decoding them as the length, if it is in the interval and the upper bound is in 0x1000000..0xFFFFFFFF") {
        checkAll(10, Arb.uIntRange(0U..(0xfffFFffeU), 0x1000000U..0xffffffffU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.uInt(interval).flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 24,
                  l shrToByte 16,
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldNotRaise {
              length.decode(slice).also { (decoded, remaining) ->
                remaining.size shouldBe slice.size - 4U
                remaining.firstIndex shouldBe slice.firstIndex + 4U
                remaining.lastIndex shouldBe slice.lastIndex

                decoded shouldBe l
              }
            }
          }
        }
      }

      should("consume one byte if the upper bound is <= 0xFF, and reject it if it is outside the interval") {
        checkAll(10, Arb.uIntRange(1U..253U, 2U..254U)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.choice(
              Arb.uInt(0U..<interval.first),
              Arb.uInt((interval.last + 1U)..255U),
            ).flatMap { l ->
              Arb.slice(
                byteArrayOf(l.toByte()),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 1U)
          }
        }
      }

      should("consume two bytes if the upper bound is in 0x100..0xFFFF, and reject it if it is outside the interval") {
        checkAll(10, Arb.uIntRange(0x1U..0xFFFDU, 0x100U..0xFFFEU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.choice(
              Arb.uInt(0U..<interval.first),
              Arb.uInt((interval.last + 1U)..0xFFFFU),
            ).flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 1U)
          }
        }
      }

      should("consume three bytes if the upper bound is in 0x10000..0xFFFFFF, and reject it if it is outside the interval") {
        checkAll(10, Arb.uIntRange(0x1U..0xFFFFFDU, 0x10000U..0xFFFFFEU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.choice(
              Arb.uInt(0U..<interval.first),
              Arb.uInt((interval.last + 1U)..0xFFFFFFU),
            ).flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 16,
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 1U)
          }
        }
      }

      should("consume four bytes if the upper bound is in 0x1000000..0xFFFFFFFF, and reject it if it is outside the interval") {
        checkAll(10, Arb.uIntRange(0x1U..0xFFFFFFFDU, 0x1000000U..0xFFFFFFFEU)) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint8) }

          checkAll(
            100,
            Arb.choice(
              Arb.uInt(0U..<interval.first),
              Arb.uInt((interval.last + 1U)..0xFFFFFFFFU),
            ).flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 24,
                  l shrToByte 16,
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 1U)
          }
        }
      }

      should("consume one byte if the upper bound is <= 0xFF, and reject it if it is not a multiple of the data type width") {
        checkAll(
          10,
          Arb.uIntRange(1U..0x7FU, 0x80U..0xFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U },
        ) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint16) }

          checkAll(
            100,
            Arb.uInt(interval).filter {
              it % 2U == 1U
            }.flatMap { l ->
              Arb.slice(
                byteArrayOf(l.toByte()),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 2U)
          }
        }
      }

      should("consume two bytes if the upper bound is in 0x100..0xFFFF, and reject it if it is not a multiple of the data type width") {
        checkAll(
          10,
          Arb.uIntRange(0x1U..0x7FFFU, 0x8000U..0xFFFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U },
        ) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint16) }

          checkAll(
            100,
            Arb.uInt(interval).filter {
              it % 2U == 1U
            }.flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 2U)
          }
        }
      }

      should(
        "consume three bytes if the upper bound is in 0x10000..0xFFFFFF, and reject it if it is not a multiple of the data type width",
      ) {
        checkAll(
          10,
          Arb.uIntRange(0x1U..0x7FFFFFU, 0x800000U..0xFFFFFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U },
        ) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint16) }

          checkAll(
            100,
            Arb.uInt(interval).filter {
              it % 2U == 1U
            }.flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 16,
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 2U)
          }
        }
      }

      should(
        "consume four bytes if the upper bound is in 0x1000000..0xFFFFFFFF, and reject it if it is not a multiple of the data type width",
      ) {
        checkAll(
          10,
          Arb.uIntRange(0x1U..0x7FFFFFFFU, 0x80000000U..0xFFFFFFFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U },
        ) { interval ->
          val length = shouldNotRaise { IntervalLength.of(interval, uint16) }

          checkAll(
            100,
            Arb.uInt(interval).filter {
              it % 2U == 1U
            }.flatMap { l ->
              Arb.slice(
                byteArrayOf(
                  l shrToByte 24,
                  l shrToByte 16,
                  l shrToByte 8,
                  l.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to l }
            },
          ) { (slice, l) ->
            shouldRaise<DecoderError.BadLength> {
              length.decode(slice)
            } shouldBe DecoderError.BadLength(slice.firstIndex, l, interval, 2U)
          }
        }
      }

      should("raise an error if there are no bytes remaining and the upper bound is in 0x0..0xFF") {
        checkAll(
          Arb.uIntRange(0U..0xFEU, 1U..0xFFU),
          Arb.slice(byteArrayOf(), alreadyConsumedLength = 0U..128U),
        ) { interval, slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            IntervalLength.of(interval, uint8).decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)
        }
      }

      should("raise an error if there are less than two bytes remaining and the upper bound is in 0x100..0xFFFF") {
        checkAll(
          Arb.uIntRange(0U..0xFFFEU, 0x100U..0xFFFFU),
          Arb.slice(Arb.byteArray(0..1), alreadyConsumedLength = 0U..128U),
        ) { interval, slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            IntervalLength.of(interval, uint8).decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 2U, slice.size)
        }
      }

      should("raise an error if there are less than three bytes remaining and the upper bound is in 0x10000..0xFFFFFF") {
        checkAll(
          Arb.uIntRange(0U..0xFFFFFEU, 0x10000U..0xFFFFFFU),
          Arb.slice(Arb.byteArray(0..2), alreadyConsumedLength = 0U..128U),
        ) { interval, slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            IntervalLength.of(interval, uint8).decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 3U, slice.size)
        }
      }

      should("raise an error if there are less than four bytes remaining and the upper bound is in 0x1990000..0xFFFFFFFF") {
        checkAll(
          Arb.uIntRange(0U..0xFFFFFFFEU, 0x1000000U..0xFFFFFFFFU),
          Arb.slice(Arb.byteArray(0..3), alreadyConsumedLength = 0U..128U),
        ) { interval, slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            IntervalLength.of(interval, uint8).decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 4U, slice.size)
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength based on the byte length of the range maximum") {
        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..0x7FU).filter { it % 2U == 0U },
            Arb.uInt(0x80U..0xFFU).filter { it % 2U == 0U },
          ),
        ) {
          shouldNotRaise { IntervalLength.of(it, uint8) }.encodedLength shouldBe 1U
          shouldNotRaise { IntervalLength.of(it, uint16) }.encodedLength shouldBe 1U
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..0x7FFFU).filter { it % 2U == 0U },
            Arb.uInt(0x8000U..0xFFFFU).filter { it % 2U == 0U },
          ),
        ) {
          shouldNotRaise { IntervalLength.of(it, uint8) }.encodedLength shouldBe 2U
          shouldNotRaise { IntervalLength.of(it, uint16) }.encodedLength shouldBe 2U
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..0x7FFFFFU).filter { it % 2U == 0U },
            Arb.uInt(0x800000U..0xFFFFFFU).filter { it % 2U == 0U },
          ),
        ) {
          shouldNotRaise { IntervalLength.of(it, uint8) }.encodedLength shouldBe 3U
          shouldNotRaise { IntervalLength.of(it, uint16) }.encodedLength shouldBe 3U
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..0x7FFFFFFFU).filter { it % 2U == 0U },
            Arb.uInt(0x80000000U..0xFFFFFFFFU).filter { it % 2U == 0U },
          ),
        ) {
          shouldNotRaise { IntervalLength.of(it, uint8) }.encodedLength shouldBe 4U
          shouldNotRaise { IntervalLength.of(it, uint16) }.encodedLength shouldBe 4U
        }
      }

      should("have a name of <min..max>") {
        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..0x7FFFFFFFU).filter { it % 2U == 0U },
            Arb.uInt(0x80000000U..0xFFFFFFFFU).filter { it % 2U == 0U },
          ),
        ) {
          shouldNotRaise { IntervalLength.of(it, uint8) }.name shouldBe "<${it.first}..${it.last}>"
          shouldNotRaise { IntervalLength.of(it, uint16) }.name shouldBe "<${it.first}..${it.last}>"
        }
      }
    }

    context(".of(interval, dataType)") {
      should("return IntervalLength(interval, sizeof(dataType)) if the data type has a Interval size") {
        checkAll(Arb.uIntRange(0U..<512U, 512U..1024U)) { interval ->
          shouldNotRaise {
            IntervalLength.of(interval, uint8).also {
              it.range shouldBe interval
              it.mod shouldBe 1U
            }
          }
        }

        checkAll(
          Arb.uIntRange(0U..<512U, 512U..1024U).filter { it.first % 2U == 0U && it.last % 2U == 0U },
        ) { interval ->
          shouldNotRaise {
            IntervalLength.of(interval, uint16).also {
              it.range shouldBe interval
              it.mod shouldBe 2U
            }
          }
        }

        checkAll(
          Arb.uIntRange(0U..<512U, 512U..1024U).filter { it.first % 3U == 0U && it.last % 3U == 0U },
        ) { interval ->
          shouldNotRaise {
            IntervalLength.of(interval, uint24).also {
              it.range shouldBe interval
              it.mod shouldBe 3U
            }
          }
        }

        checkAll(
          Arb.uIntRange(0U..<512U, 512U..1024U).filter { it.first % 4U == 0U && it.last % 4U == 0U },
        ) { interval ->
          shouldNotRaise {
            IntervalLength.of(interval, uint32).also {
              it.range shouldBe interval
              it.mod shouldBe 4U
            }
          }
        }

        checkAll(
          Arb.uIntRange(0U..<512U, 512U..1024U).filter { it.first % 8U == 0U && it.last % 8U == 0U },
        ) { interval ->
          shouldNotRaise {
            IntervalLength.of(interval, uint64).also {
              it.range shouldBe interval
              it.mod shouldBe 8U
            }
          }
        }

        checkAll(
          Arb.uIntRange(0U..<512U, 512U..1024U).filter { it.first % 4U == 0U && it.last % 4U == 0U },
        ) { interval ->
          shouldNotRaise {
            IntervalLength.of(interval, uint16[4U]).also {
              it.range shouldBe interval
              it.mod shouldBe 4U
            }
          }
        }

        checkAll(
          Arb.uIntRange(0U..<512U, 512U..1024U).filter { it.first % 24U == 0U && it.last % 24U == 0U },
        ) { interval ->
          shouldNotRaise {
            IntervalLength.of(interval, opaque[24U]).also {
              it.range shouldBe interval
              it.mod shouldBe 24U
            }
          }
        }

        checkAll(
          Arb.uIntRange(0U..<512U, 512U..1024U).filter { it.first % 10U == 0U && it.last % 10U == 0U },
        ) { interval ->
          shouldNotRaise {
            IntervalLength.of(
              interval,
              struct("test") {
                it.field("short", uint16)
                  .field("long", uint64)
              },
            ).also {
              it.range shouldBe interval
              it.mod shouldBe 10U
            }
          }
        }
      }

      should("raise an error if dataType has no known size") {
        checkAll(Arb.uIntRange(0U..1024U, 1U..1025U)) {
          shouldRaise<LengthError.UndefinedLength> {
            IntervalLength.of(it, uint8[V])
          }.also {
            it.lengthType shouldBe "interval"
            it.dataType shouldBe "uint8<V>"
          }
          shouldRaise<LengthError.UndefinedLength> {
            IntervalLength.of(it, uint8[10U..20U])
          }.also {
            it.lengthType shouldBe "interval"
            it.dataType shouldBe "uint8<10..20>"
          }
        }
      }

      should("raise an error if the range is empty") {
        checkAll(Arb.uIntRange(512U..1023U, 0U..511U, allowEmpty = true)) {
          shouldRaise<LengthError.BadRange> {
            IntervalLength.of(it, uint8)
          } shouldBe LengthError.BadRange(it)

          shouldRaise<LengthError.BadRange> {
            IntervalLength.of(it, uint16)
          } shouldBe LengthError.BadRange(it)

          shouldRaise<LengthError.BadRange> {
            IntervalLength.of(it, opaque[24U])
          } shouldBe LengthError.BadRange(it)
        }
      }

      should("raise an error if the range start is not a multiple of the data type size") {
        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 2U != 0U },
            Arb.uInt(512U..1024U).filter { it % 2U == 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint16)
          } shouldBe LengthError.BadLength(interval.first, "uint16", 2U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 3U != 0U },
            Arb.uInt(512U..1024U).filter { it % 3U == 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint24)
          } shouldBe LengthError.BadLength(interval.first, "uint24", 3U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 4U != 0U },
            Arb.uInt(512U..1024U).filter { it % 4U == 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint32)
          } shouldBe LengthError.BadLength(interval.first, "uint32", 4U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 8U != 0U },
            Arb.uInt(512U..1024U).filter { it % 8U == 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint64)
          } shouldBe LengthError.BadLength(interval.first, "uint64", 8U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 4U != 0U },
            Arb.uInt(512U..1024U).filter { it % 4U == 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint16[4U])
          } shouldBe LengthError.BadLength(interval.first, "uint16[4]", 4U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 24U != 0U },
            Arb.uInt(512U..1024U).filter { it % 24U == 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, opaque[24U])
          } shouldBe LengthError.BadLength(interval.first, "opaque[24]", 24U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 10U != 0U },
            Arb.uInt(512U..1024U).filter { it % 10U == 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(
              interval,
              struct("test") {
                it.field("short", uint16)
                  .field("long", uint64)
              },
            )
          } shouldBe LengthError.BadLength(interval.first, "test", 10U)
        }
      }

      should("raise an error if the range end is not a multiple of the data type size") {
        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 2U == 0U },
            Arb.uInt(512U..1024U).filter { it % 2U != 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint16)
          } shouldBe LengthError.BadLength(interval.last, "uint16", 2U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 3U == 0U },
            Arb.uInt(512U..1024U).filter { it % 3U != 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint24)
          } shouldBe LengthError.BadLength(interval.last, "uint24", 3U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 4U == 0U },
            Arb.uInt(512U..1024U).filter { it % 4U != 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint32)
          } shouldBe LengthError.BadLength(interval.last, "uint32", 4U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 8U == 0U },
            Arb.uInt(512U..1024U).filter { it % 8U != 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint64)
          } shouldBe LengthError.BadLength(interval.last, "uint64", 8U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 4U == 0U },
            Arb.uInt(512U..1024U).filter { it % 4U != 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, uint16[4U])
          } shouldBe LengthError.BadLength(interval.last, "uint16[4]", 4U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 24U == 0U },
            Arb.uInt(512U..1024U).filter { it % 24U != 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(interval, opaque[24U])
          } shouldBe LengthError.BadLength(interval.last, "opaque[24]", 24U)
        }

        checkAll(
          Arb.uIntRange(
            Arb.uInt(0U..<512U).filter { it % 10U == 0U },
            Arb.uInt(512U..1024U).filter { it % 10U != 0U },
          ),
        ) { interval ->
          shouldRaise<LengthError.BadLength> {
            IntervalLength.of(
              interval,
              struct("test") {
                it.field("short", uint16)
                  .field("long", uint64)
              },
            )
          } shouldBe LengthError.BadLength(interval.last, "test", 10U)
        }
      }
    }
  }

  context("VariableLength") {
    should("decode a length that it previously encoded") {
      checkAll(Arb.uInt(0U..32768U)) {
        shouldNotRaise { V(uint8).decode(V(uint8).encode(it).full).done() shouldBe it }
      }
    }

    context("when encoding") {
      should("encode the length with a single byte and a 00 tag if it is <= 0x3F") {
        checkAll(Arb.uInt(v1Byte)) {
          shouldNotRaise { V(uint8).encode(it) shouldBe byteArrayOf(it.toByte()) }
        }
      }

      should("encode the length with two bytes and a 01 tag if it is in 0x40..0x3FFF") {
        checkAll(Arb.uInt(v2Bytes)) {
          shouldNotRaise {
            V(uint8).encode(it) shouldBe
              byteArrayOf(
                it shrToByte 8 or 0x40.toByte(),
                it.toByte(),
              )
          }
        }
      }

      should("encode the length with four bytes and a 10 tag if it is in 0x4000..0x3FFFFFFF") {
        checkAll(Arb.uInt(v4Bytes)) {
          shouldNotRaise {
            V(uint8).encode(it) shouldBe
              byteArrayOf(
                it shrToByte 24 or 0x80.toByte(),
                it shrToByte 16,
                it shrToByte 8,
                it.toByte(),
              )
          }
        }
      }

      should("raise an error if the length is >= 0x40000000") {
        checkAll(Arb.uInt(min = 0x40000000U)) {
          shouldRaise<EncoderError.BadLength> { V(uint8).encode(it) }
        }
      }

      should("raise an error if the length is not a multiple of the data type size, if any") {
        checkAll(Arb.uInt(0U..0x3FFFFFFFU).filter { it % 2U != 0U }) {
          shouldRaise<EncoderError.BadLength> { V(uint16).encode(it) }
        }

        checkAll(Arb.uInt(0U..0x3FFFFFFFU).filter { it % 3U != 0U }) {
          shouldRaise<EncoderError.BadLength> { V(uint24).encode(it) }
        }

        checkAll(Arb.uInt(0U..0x3FFFFFFFU).filter { it % 4U != 0U }) {
          shouldRaise<EncoderError.BadLength> { V(uint32).encode(it) }
        }
      }
    }

    context("when decoding") {
      should("consume one byte, decoding it as the length, if it has the tag 00") {
        checkAll(
          Arb.uInt(v1Byte).flatMap { l ->
            Arb.slice(
              byteArrayOf(l.toByte()),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to l }
          },
        ) { (slice, l) ->
          shouldNotRaise {
            V(uint8).decode(slice).also { (decoded, remaining) ->
              remaining.size shouldBe slice.size - 1U
              remaining.firstIndex shouldBe slice.firstIndex + 1U
              remaining.lastIndex shouldBe slice.lastIndex

              decoded shouldBe l
            }
          }
        }
      }

      should("consume two bytes, decoding them as the length, if the first byte has the tag 01") {
        checkAll(
          Arb.uInt(v2Bytes).flatMap { l ->
            Arb.slice(
              byteArrayOf(
                l shrToByte 8 or 0x40.toByte(),
                l.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to l }
          },
        ) { (slice, l) ->
          shouldNotRaise {
            V(uint8).decode(slice).also { (decoded, remaining) ->
              remaining.size shouldBe slice.size - 2U
              remaining.firstIndex shouldBe slice.firstIndex + 2U
              remaining.lastIndex shouldBe slice.lastIndex

              decoded shouldBe l
            }
          }
        }
      }

      should("consume four bytes, decoding them as the length, if the first byte has the tag 10") {
        checkAll(
          Arb.uInt(v4Bytes).flatMap { l ->
            Arb.slice(
              byteArrayOf(
                l shrToByte 24 or 0x80.toByte(),
                l shrToByte 16,
                l shrToByte 8,
                l.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to l }
          },
        ) { (slice, l) ->
          shouldNotRaise {
            V(uint8).decode(slice).also { (decoded, remaining) ->
              remaining.size shouldBe slice.size - 4U
              remaining.firstIndex shouldBe slice.firstIndex + 4U
              remaining.lastIndex shouldBe slice.lastIndex

              decoded shouldBe l
            }
          }
        }
      }

      should("raise an error if the first byte has the tag 11") {
        checkAll(
          Arb.slice(
            Arb.byteArray(1..1024).filter { it[0].toInt() and 0xC0 == 0xC0 },
            alreadyConsumedLength = 0U..128U,
            extraLength = 0U..128U,
          ),
        ) {
          shouldRaise<DecoderError.InvalidLengthEncoding> {
            V(uint8).decode(it)
          } shouldBe DecoderError.InvalidLengthEncoding(it.firstIndex)
        }
      }

      should("raise an error if there are no bytes remaining") {
        checkAll(
          Arb.slice(byteArrayOf(), alreadyConsumedLength = 0U..128U),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            V(uint8).decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)
        }
      }

      should("raise an error if there are less than two bytes remaining and the first byte has the tag 01") {
        checkAll(
          Arb.slice(
            Arb.byteArray(1).filter { it[0].toInt() and 0xC0 == 0x40 },
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            V(uint8).decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 1U, slice.size - 1U)
        }
      }

      should("raise an error if there are less than four bytes remaining and the first byte has the tag 10") {
        checkAll(
          Arb.slice(
            Arb.byteArray(1..3).filter { it[0].toInt() and 0xC0 == 0x80 },
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            V(uint8).decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 3U, slice.size - 1U)
        }
      }

      should("raise an error if the decoded length is not a multiple of the data type width") {
        checkAll(
          Arb.uInt(0U..0x3FFFFFFFU).filter { it % 2U != 0U }.flatMap { length ->
            Arb.slice(
              shouldNotRaise { V(uint8).encode(length) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to length }
          },
        ) { (slice, length) ->
          shouldRaise<DecoderError.BadLength> {
            V(uint16).decode(slice)
          } shouldBe DecoderError.BadLength(slice.firstIndex, length, 0U..0x3FFFFFFFU, 2U)
        }

        checkAll(
          Arb.uInt(0U..0x3FFFFFFFU).filter { it % 3U != 0U }.flatMap { length ->
            Arb.slice(
              shouldNotRaise { V(uint8).encode(length) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to length }
          },
        ) { (slice, length) ->
          shouldRaise<DecoderError.BadLength> {
            V(uint24).decode(slice)
          } shouldBe DecoderError.BadLength(slice.firstIndex, length, 0U..0x3FFFFFFFU, 3U)
        }

        checkAll(
          Arb.uInt(0U..0x3FFFFFFFU).filter { it % 4U != 0U }.flatMap { length ->
            Arb.slice(
              shouldNotRaise { V(uint8).encode(length) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to length }
          },
        ) { (slice, length) ->
          shouldRaise<DecoderError.BadLength> {
            V(uint32).decode(slice)
          } shouldBe DecoderError.BadLength(slice.firstIndex, length, 0U..0x3FFFFFFFU, 4U)
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have no encodedLength") {
        V(uint8).encodedLength.shouldBeNull()
      }

      should("have a name of <V>") {
        V(uint8).name shouldBe "<V>"
      }
    }

    context(".of(dataType)") {
      should("capture the data type's size, if it is known") {
        V(uint8).shouldBeInstanceOf<VariableLength>().mod shouldBe 1U
        V(uint16).shouldBeInstanceOf<VariableLength>().mod shouldBe 2U
        V(uint24).shouldBeInstanceOf<VariableLength>().mod shouldBe 3U
        V(uint32).shouldBeInstanceOf<VariableLength>().mod shouldBe 4U
        V(uint64).shouldBeInstanceOf<VariableLength>().mod shouldBe 8U
        shouldNotRaise { V(uint16[8U]) }.shouldBeInstanceOf<VariableLength>().mod shouldBe 8U
        V(opaque[24U]).shouldBeInstanceOf<VariableLength>().mod shouldBe 24U

        V(optional[uint32]).shouldBeInstanceOf<VariableLength>().mod.shouldBeNull()
      }
    }
  }
})
