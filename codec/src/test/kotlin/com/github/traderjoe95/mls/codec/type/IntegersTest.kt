package com.github.traderjoe95.mls.codec.type

import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.IntegerError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.type.DataType.Companion.done
import com.github.traderjoe95.mls.codec.uInt16
import com.github.traderjoe95.mls.codec.uInt24
import com.github.traderjoe95.mls.codec.uInt32
import com.github.traderjoe95.mls.codec.uInt64
import com.github.traderjoe95.mls.codec.uInt8
import com.github.traderjoe95.mls.codec.util.full
import com.github.traderjoe95.mls.codec.util.shrToByte
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.uByte
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.arbitrary.uShort
import io.kotest.property.checkAll

class IntegersTest : ShouldSpec({
  context("uint8") {
    should("encode all possible UInt8 values correctly") {
      checkAll(Arb.uInt8()) {
        shouldNotRaise {
          uint8.encode(it) shouldBe byteArrayOf(it.toByte())
        }
      }
    }

    context("when decoding") {
      should("decode all possible UInt8 values correctly, consuming all remaining bytes if there is only one") {
        checkAll(
          Arb.uInt8().flatMap { value ->
            Arb.slice(
              byteArrayOf(value.toByte()),
              alreadyConsumedLength = 0U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint8.decode(slice).done() shouldBe value
          }
        }
      }

      should("decode all possible UInt8 values correctly, consuming only one byte if there are more than one") {
        checkAll(
          Arb.uInt8().flatMap { value ->
            Arb.slice(
              byteArrayOf(value.toByte()),
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint8.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.firstIndex shouldBe slice.firstIndex + 1U
              remaining.lastIndex shouldBe slice.lastIndex
              remaining.size shouldBe slice.size - 1U

              decoded shouldBe value
            }
          }
        }
      }

      should("raise an error if there are no bytes remaining") {
        checkAll(
          Arb.slice(
            byteArrayOf(),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8.decode(slice)
          }.also {
            it.position shouldBe slice.firstIndex
            it.expectedBytes shouldBe 1U
            it.remaining shouldBe 0U
          }
        }
      }
    }

    should("be able to decode what it encoded previously") {
      checkAll(Arb.uInt8()) {
        shouldNotRaise {
          uint8.decode(uint8.encode(it).full).done() shouldBe it
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of 1") {
        uint8.encodedLength shouldBe 1U
      }

      should("have a name of uint8") {
        uint8.name shouldBe "uint8"
      }
    }

    context(".asUByte") {
      should("encode all possible UByte values correctly") {
        checkAll(Arb.uByte()) {
          shouldNotRaise {
            uint8.asUByte.encode(it) shouldBe byteArrayOf(it.toByte())
          }
        }
      }

      should("decode all possible UByte values correctly") {
        checkAll(Arb.uByte()) {
          shouldNotRaise {
            uint8.asUByte.decode(byteArrayOf(it.toByte()).full).done() shouldBe it
          }
        }
      }

      should("be able to decode what it encoded previously") {
        checkAll(Arb.uByte()) {
          shouldNotRaise {
            uint8.asUByte.decode(uint8.asUByte.encode(it).full).done() shouldBe it
          }
        }
      }

      context("should have DataType<V>'s properties") {
        should("have an encodedLength of 1") {
          uint8.asUByte.encodedLength shouldBe 1U
        }

        should("have a name of uint8") {
          uint8.asUByte.name shouldBe "uint8"
        }
      }
    }
  }

  context("uint16") {
    should("encode all possible UInt16 values correctly to big-endian") {
      checkAll(Arb.uInt16()) {
        shouldNotRaise {
          uint16.encode(it) shouldBe
            byteArrayOf(
              it shrToByte 8,
              it.toByte(),
            )
        }
      }
    }

    context("when decoding") {
      should("decode all possible UInt16 values correctly, consuming all remaining bytes if there are only two") {
        checkAll(
          Arb.uInt16().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint16.decode(slice).done() shouldBe value
          }
        }
      }

      should("decode all possible UInt16 values correctly, consuming only two bytes if there are more than two") {
        checkAll(
          Arb.uInt16().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint16.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.firstIndex shouldBe slice.firstIndex + 2U
              remaining.lastIndex shouldBe slice.lastIndex
              remaining.size shouldBe slice.size - 2U

              decoded shouldBe value
            }
          }
        }
      }

      should("raise an error if there are less than two bytes remaining") {
        checkAll(
          Arb.slice(
            Arb.byteArray(0..1),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16.decode(slice)
          }.also {
            it.position shouldBe slice.firstIndex
            it.expectedBytes shouldBe 2U
            it.remaining shouldBe slice.size
          }
        }
      }
    }

    should("be able to decode what it encoded previously") {
      checkAll(Arb.uInt16()) {
        shouldNotRaise {
          uint16.decode(uint16.encode(it).full).done() shouldBe it
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of 2") {
        uint16.encodedLength shouldBe 2U
      }

      should("have a name of uint16") {
        uint16.name shouldBe "uint16"
      }
    }

    context(".asUShort") {
      should("encode all possible UShort values correctly to big-endian") {
        checkAll(Arb.uShort()) {
          shouldNotRaise {
            uint16.asUShort.encode(it) shouldBe
              byteArrayOf(
                it shrToByte 8,
                it.toByte(),
              )
          }
        }
      }

      should("decode all possible UShort values correctly from big-endian") {
        checkAll(Arb.uShort()) {
          shouldNotRaise {
            uint16.asUShort.decode(
              byteArrayOf(
                it shrToByte 8,
                it.toByte(),
              ).full,
            ).done() shouldBe it
          }
        }
      }

      should("be able to decode what it encoded previously") {
        checkAll(Arb.uShort()) {
          shouldNotRaise {
            uint16.asUShort.decode(uint16.asUShort.encode(it).full).done() shouldBe it
          }
        }
      }

      context("should have DataType<V>'s properties") {
        should("have an encodedLength of 2") {
          uint16.asUShort.encodedLength shouldBe 2U
        }

        should("have a name of uint16") {
          uint16.asUShort.name shouldBe "uint16"
        }
      }
    }
  }

  context("uint24") {
    should("encode all possible UInt24 values correctly to big-endian") {
      checkAll(Arb.uInt24()) {
        shouldNotRaise {
          uint24.encode(it) shouldBe
            byteArrayOf(
              it shrToByte 16,
              it shrToByte 8,
              it.toByte(),
            )
        }
      }
    }

    context("when decoding") {
      should("decode all possible UInt24 values correctly, consuming all remaining bytes if there are only three") {
        checkAll(
          Arb.uInt24().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 16,
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint24.decode(slice).done() shouldBe value
          }
        }
      }

      should("decode all possible UInt24 values correctly, consuming only three bytes if there are more than three") {
        checkAll(
          Arb.uInt24().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 16,
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint24.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.firstIndex shouldBe slice.firstIndex + 3U
              remaining.lastIndex shouldBe slice.lastIndex
              remaining.size shouldBe slice.size - 3U

              decoded shouldBe value
            }
          }
        }
      }

      should("raise an error if there are less than three bytes remaining") {
        checkAll(
          Arb.slice(
            Arb.byteArray(0..2),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint24.decode(slice)
          }.also {
            it.position shouldBe slice.firstIndex
            it.expectedBytes shouldBe 3U
            it.remaining shouldBe slice.size
          }
        }
      }
    }

    should("be able to decode what it encoded previously") {
      checkAll(Arb.uInt24()) {
        shouldNotRaise {
          uint24.decode(uint24.encode(it).full).done() shouldBe it
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of 3") {
        uint24.encodedLength shouldBe 3U
      }

      should("have a name of uint24") {
        uint24.name shouldBe "uint24"
      }
    }

    context(".asUInt") {
      should("encode all possible 3-byte UInt values correctly to big-endian") {
        checkAll(Arb.uInt(0U..0x00FFFFFFU)) {
          shouldNotRaise {
            uint24.asUInt.encode(it) shouldBe
              byteArrayOf(
                it shrToByte 16,
                it shrToByte 8,
                it.toByte(),
              )
          }
        }
      }

      should("decode all possible UInt values correctly from big-endian") {
        checkAll(Arb.uInt(0U..0x00FFFFFFU)) {
          shouldNotRaise {
            uint24.asUInt.decode(
              byteArrayOf(
                it shrToByte 16,
                it shrToByte 8,
                it.toByte(),
              ).full,
            ).done() shouldBe it
          }
        }
      }

      should("be able to decode what it encoded previously") {
        checkAll(Arb.uInt(0U..0x00FFFFFFU)) {
          shouldNotRaise {
            uint24.asUInt.decode(uint24.asUInt.encode(it).full).done() shouldBe it
          }
        }
      }

      should("raise an error when trying to encode a four-byte value") {
        checkAll(Arb.uInt(0x01000000U..0xFFFFFFFFU)) {
          shouldRaise<IntegerError.ValueTooBig> {
            uint24.asUInt.encode(it)
          } shouldBe IntegerError.ValueTooBig("uint24", it)
        }
      }

      context("should have DataType<V>'s properties") {
        should("have an encodedLength of 3") {
          uint24.asUInt.encodedLength shouldBe 3U
        }

        should("have a name of uint24") {
          uint24.asUInt.name shouldBe "uint24"
        }
      }
    }
  }

  context("uint32") {
    should("encode all possible UInt32 values correctly to big-endian") {
      checkAll(Arb.uInt32()) {
        shouldNotRaise {
          uint32.encode(it) shouldBe
            byteArrayOf(
              it shrToByte 24,
              it shrToByte 16,
              it shrToByte 8,
              it.toByte(),
            )
        }
      }
    }

    context("when decoding") {
      should("decode all possible UInt32 values correctly, consuming all remaining bytes if there are only four") {
        checkAll(
          Arb.uInt32().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 24,
                value shrToByte 16,
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint32.decode(slice).done() shouldBe value
          }
        }
      }

      should("decode all possible UInt32 values correctly, consuming only four bytes if there are more than four") {
        checkAll(
          Arb.uInt32().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 24,
                value shrToByte 16,
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint32.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.firstIndex shouldBe slice.firstIndex + 4U
              remaining.lastIndex shouldBe slice.lastIndex
              remaining.size shouldBe slice.size - 4U

              decoded shouldBe value
            }
          }
        }
      }

      should("raise an error if there are less than four bytes remaining") {
        checkAll(
          Arb.slice(
            Arb.byteArray(0..3),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint32.decode(slice)
          }.also {
            it.position shouldBe slice.firstIndex
            it.expectedBytes shouldBe 4U
            it.remaining shouldBe slice.size
          }
        }
      }
    }

    should("be able to decode what it encoded previously") {
      checkAll(Arb.uInt32()) {
        shouldNotRaise {
          uint32.decode(uint32.encode(it).full).done() shouldBe it
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of 4") {
        uint32.encodedLength shouldBe 4U
      }

      should("have a name of uint8") {
        uint32.name shouldBe "uint32"
      }
    }

    context(".asUInt") {
      should("encode all possible UInt values correctly to big-endian") {
        checkAll(Arb.uInt()) {
          shouldNotRaise {
            uint32.asUInt.encode(it) shouldBe
              byteArrayOf(
                it shrToByte 24,
                it shrToByte 16,
                it shrToByte 8,
                it.toByte(),
              )
          }
        }
      }

      should("decode all possible UInt values correctly from big-endian") {
        checkAll(Arb.uInt()) {
          shouldNotRaise {
            uint32.asUInt.decode(
              byteArrayOf(
                it shrToByte 24,
                it shrToByte 16,
                it shrToByte 8,
                it.toByte(),
              ).full,
            ).done() shouldBe it
          }
        }
      }

      should("be able to decode what it encoded previously") {
        checkAll(Arb.uInt()) {
          shouldNotRaise {
            uint32.asUInt.decode(uint32.asUInt.encode(it).full).done() shouldBe it
          }
        }
      }

      context("should have DataType<V>'s properties") {
        should("have an encodedLength of 4") {
          uint32.asUInt.encodedLength shouldBe 4U
        }

        should("have a name of uint32") {
          uint32.asUInt.name shouldBe "uint32"
        }
      }
    }
  }

  context("uint64") {
    should("encode all possible UInt64 values correctly to big-endian") {
      checkAll(Arb.uInt64()) {
        shouldNotRaise {
          uint64.encode(it) shouldBe
            byteArrayOf(
              it shrToByte 56,
              it shrToByte 48,
              it shrToByte 40,
              it shrToByte 32,
              it shrToByte 24,
              it shrToByte 16,
              it shrToByte 8,
              it.toByte(),
            )
        }
      }
    }

    context("when decoding") {
      should("decode all possible UInt64 values correctly, consuming all remaining bytes if there are only eight") {
        checkAll(
          Arb.uInt64().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 56,
                value shrToByte 48,
                value shrToByte 40,
                value shrToByte 32,
                value shrToByte 24,
                value shrToByte 16,
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint64.decode(slice).done() shouldBe value
          }
        }
      }

      should("decode all possible UInt64 values correctly, consuming only eight bytes if there are more than eight") {
        checkAll(
          Arb.uInt64().flatMap { value ->
            Arb.slice(
              byteArrayOf(
                value shrToByte 56,
                value shrToByte 48,
                value shrToByte 40,
                value shrToByte 32,
                value shrToByte 24,
                value shrToByte 16,
                value shrToByte 8,
                value.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { it to value }
          },
        ) { (slice, value) ->
          shouldNotRaise {
            uint64.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.firstIndex shouldBe slice.firstIndex + 8U
              remaining.lastIndex shouldBe slice.lastIndex
              remaining.size shouldBe slice.size - 8U

              decoded shouldBe value
            }
          }
        }
      }

      should("raise an error if there are less than eight bytes remaining") {
        checkAll(
          Arb.slice(
            Arb.byteArray(0..7),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint64.decode(slice)
          }.also {
            it.position shouldBe slice.firstIndex
            it.expectedBytes shouldBe 8U
            it.remaining shouldBe slice.size
          }
        }
      }
    }

    should("be able to decode what it encoded previously") {
      checkAll(Arb.uInt64()) {
        shouldNotRaise {
          uint64.decode(uint64.encode(it).full).done() shouldBe it
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of 8") {
        uint64.encodedLength shouldBe 8U
      }

      should("have a name of uint64") {
        uint64.name shouldBe "uint64"
      }
    }

    context(".asULong") {
      should("encode all possible ULong values correctly to big-endian") {
        checkAll(Arb.uLong()) {
          shouldNotRaise {
            uint64.asULong.encode(it) shouldBe
              byteArrayOf(
                it shrToByte 56,
                it shrToByte 48,
                it shrToByte 40,
                it shrToByte 32,
                it shrToByte 24,
                it shrToByte 16,
                it shrToByte 8,
                it.toByte(),
              )
          }
        }
      }

      should("decode all possible ULong values correctly from big-endian") {
        checkAll(Arb.uLong()) {
          shouldNotRaise {
            uint64.asULong.decode(
              byteArrayOf(
                it shrToByte 56,
                it shrToByte 48,
                it shrToByte 40,
                it shrToByte 32,
                it shrToByte 24,
                it shrToByte 16,
                it shrToByte 8,
                it.toByte(),
              ).full,
            ).done() shouldBe it
          }
        }
      }

      should("be able to decode what it encoded previously") {
        checkAll(Arb.uLong()) {
          shouldNotRaise {
            uint64.asULong.decode(uint64.asULong.encode(it).full).done() shouldBe it
          }
        }
      }

      context("should have DataType<V>'s properties") {
        should("have an encodedLength of 8") {
          uint64.asULong.encodedLength shouldBe 8U
        }

        should("have a name of uint64") {
          uint64.asULong.name shouldBe "uint64"
        }
      }
    }
  }
})
