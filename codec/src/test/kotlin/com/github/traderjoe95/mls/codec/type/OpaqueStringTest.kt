package com.github.traderjoe95.mls.codec.type

import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.stringWithV
import com.github.traderjoe95.mls.codec.type.DataType.Companion.done
import com.github.traderjoe95.mls.codec.uIntRange
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.util.toIntRange
import com.github.traderjoe95.mls.codec.util.uSize
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.printableAscii
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class OpaqueStringTest : ShouldSpec({
  context("opaque[fixed].asUtf8String") {
    should("encode byte arrays of the correct length as themselves") {
      checkAll(Arb.string(0..1024, Codepoint.printableAscii())) {
        shouldNotRaise { opaque[it.uSize].asUtf8String.encode(it) shouldBe it.encodeToByteArray() }
      }
    }

    context("when decoding") {
      should("consume all remaining bytes when their number is the fixed length") {
        checkAll(
          Arb.string(0..1024, Codepoint.printableAscii()).map { it.encodeToByteArray() }.flatMap { bytes ->
            Arb.slice(
              bytes,
              alreadyConsumedLength = 0U..128U,
            ).map { it to bytes }
          },
        ) { (slice, bytes) ->
          shouldNotRaise { opaque[bytes.uSize].asUtf8String.decode(slice).done() shouldBe bytes.decodeToString() }
        }
      }

      should("only consume fixed bytes if there are more remaining") {
        checkAll(
          Arb.string(0..1024, Codepoint.printableAscii()).map { it.encodeToByteArray() }.flatMap { bytes ->
            Arb.slice(
              bytes,
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { it to bytes }
          },
        ) { (slice, bytes) ->
          shouldNotRaise {
            opaque[bytes.uSize].asUtf8String.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.size shouldBe slice.size - bytes.uSize

              decoded shouldBe bytes.decodeToString()
            }
          }
        }
      }

      should("raise an error when there are less bytes remaining than expected") {
        checkAll(
          Arb.pair(
            Arb.string(0..1024, Codepoint.printableAscii()).map { it.encodeToByteArray() },
            Arb.uInt(1U..1025U),
          ).filter {
            it.first.uSize < it.second
          }.flatMap { (bytes, size) ->
            Arb.slice(
              bytes,
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..(size - bytes.uSize - 1U),
            ).map { it to size }
          },
        ) { (slice, size) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            opaque[size].asUtf8String.decode(slice)
          }.also {
            it.position shouldBe slice.firstIndex
            it.remaining shouldBe slice.size
            it.expectedBytes shouldBe size
          }
        }
      }
    }

    should("reject byte arrays with a length different from the fixed length") {
      checkAll(
        Arb.pair(Arb.string(0..1024, Codepoint.printableAscii()), Arb.uInt()).filter {
          it.first.uSize != it.second
        },
      ) { (bytes, fixed) ->
        shouldRaise<EncoderError.BadLength> { opaque[fixed].asUtf8String.encode(bytes) }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of fixed") {
        checkAll(Arb.uInt()) {
          opaque[it].asUtf8String.encodedLength shouldBe it
        }
      }

      should("have a name of opaque[fixed]") {
        checkAll(Arb.uInt()) {
          opaque[it].asUtf8String.name shouldBe "opaque[$it]"
        }
      }
    }
  }

  context("opaque<min..max>.asUtf8String") {
    should("encode byte arrays of the correct length as a length field plus themselves") {
      checkAll(
        Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
          it.first != it.last
        }.flatMap { range ->
          Arb.string(range.toIntRange(), Codepoint.printableAscii()).map { it to range }
        },
      ) { (string, range) ->
        shouldNotRaise {
          opaque[range].asUtf8String.encode(string) shouldBe
            byteArrayOf(
              string.uSize.toByte(),
              *string.encodeToByteArray(),
            )
        }
      }
    }

    context("when decoding") {
      should("consume all remaining bytes when their number corresponds to the length field") {
        checkAll(
          Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
            it.first != it.last
          }.flatMap { range ->
            Arb.string(range.toIntRange(), Codepoint.printableAscii()).map { it.encodeToByteArray() }.flatMap { bytes ->
              Arb.slice(
                byteArrayOf(bytes.size.toByte(), *bytes),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, bytes, range) }
            }
          },
        ) { (slice, bytes, range) ->
          shouldNotRaise {
            opaque[range].asUtf8String.decode(slice).done() shouldBe bytes.decodeToString()
          }
        }
      }

      should("only consume bytes according to the length field if there are more remaining") {
        checkAll(
          Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
            it.first != it.last
          }.flatMap { range ->
            Arb.string(range.toIntRange(), Codepoint.printableAscii()).map { it.encodeToByteArray() }.flatMap { bytes ->
              Arb.slice(
                byteArrayOf(bytes.size.toByte(), *bytes),
                alreadyConsumedLength = 0U..128U,
                extraLength = 1U..128U,
              ).map { Triple(it, bytes, range) }
            }
          },
        ) { (slice, bytes, range) ->
          shouldNotRaise {
            opaque[range].asUtf8String.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.size shouldBe slice.size - bytes.uSize - 1U

              decoded shouldBe bytes.decodeToString()
            }
          }
        }
      }

      should("raise an error when there are less bytes remaining than the length tag indicates") {
        checkAll(
          Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
            it.first != it.last
          }.flatMap { range ->
            Arb.pair(
              Arb.string(range.toIntRange(), Codepoint.printableAscii()).map { it.encodeToByteArray() },
              Arb.uInt(range),
            ).filter {
              it.first.uSize < it.second
            }.flatMap { (bytes, size) ->
              Arb.slice(
                byteArrayOf(size.toByte(), *bytes),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..(size - bytes.uSize - 1U),
              ).map { Triple(it, size, range) }
            }
          },
        ) { (slice, size, range) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            opaque[range].asUtf8String.decode(slice)
          }.also {
            it.position shouldBe slice.firstIndex + 1U
            it.remaining shouldBe slice.size - 1U
            it.expectedBytes shouldBe size
          }
        }
      }
    }

    should("reject byte arrays with a length outside the interval") {
      checkAll(
        Arb.pair(
          Arb.string(0..255, Codepoint.printableAscii()),
          Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter { it.first != it.last },
        ).filter {
          it.first.uSize !in it.second
        },
      ) { (str, range) ->
        shouldRaise<EncoderError.BadLength> { opaque[range].asUtf8String.encode(str) }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have no encodedLength") {
        checkAll(Arb.uIntRange(0x0U..0x7FFFFFFFU, 0x80000000U..0xFFFFFFFFU)) {
          shouldNotRaise { opaque[it].asUtf8String }.encodedLength.shouldBeNull()
        }
      }

      should("have a name of opaque<min..max>") {
        checkAll(Arb.uIntRange(0x0U..0x7FFFFFFFU, 0x80000000U..0xFFFFFFFFU)) {
          shouldNotRaise { opaque[it].asUtf8String }.name shouldBe "opaque<${it.first}..${it.last}>"
        }
      }
    }
  }

  context("opaque<V>.asUtf8String") {
    should("encode byte arrays of any length less than 0x00FFFFFF") {
      checkAll(
        Arb.string(0..1024, Codepoint.printableAscii()),
      ) { str ->
        shouldNotRaise {
          opaque[V].asUtf8String.encode(str) shouldBe byteArrayOf(*V(uint8).encode(str.uSize), *str.encodeToByteArray())
        }
      }
    }

    context("when decoding") {
      should("consume all remaining bytes when their number corresponds to the length field") {
        checkAll(
          Arb.stringWithV(0..1024).flatMap { (bytesWithV, str, _) ->
            Arb.slice(
              bytesWithV,
              alreadyConsumedLength = 0U..128U,
            ).map { it to str }
          },
        ) { (slice, string) ->
          shouldNotRaise {
            opaque[V].asUtf8String.decode(slice).done() shouldBe string
          }
        }
      }

      should("only consume bytes according to the length field if there are more remaining") {
        checkAll(
          Arb.stringWithV(0..1024).flatMap { (bytesWithV, str, size) ->
            Arb.slice(
              bytesWithV,
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { Triple(it, str, size) }
          },
        ) { (slice, str, size) ->
          shouldNotRaise {
            opaque[V].asUtf8String.decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.size shouldBe slice.size - size - V(uint8).encode(size).uSize

              decoded shouldBe str
            }
          }
        }
      }

      should("raise an error when there are less bytes remaining than the length tag indicates") {
        checkAll(
          Arb.pair(
            Arb.string(0..1023, Codepoint.printableAscii()),
            Arb.uInt(1U..1024U),
          ).filter {
            it.first.uSize < it.second
          }.flatMap { (str, size) ->
            Arb.slice(
              throwAnyError { byteArrayOf(*V(uint8).encode(size), *str.encodeToByteArray()) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..(size - str.uSize - 1U),
            ).map { it to size }
          },
        ) { (slice, size) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            opaque[V].asUtf8String.decode(slice)
          }.also {
            val lengthBytes = throwAnyError { V(uint8).encode(size) }.uSize

            it.position shouldBe slice.firstIndex + lengthBytes
            it.remaining shouldBe slice.size - lengthBytes
            it.expectedBytes shouldBe size
          }
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have no encodedLength") {
        opaque[V].asUtf8String.encodedLength.shouldBeNull()
      }

      should("have a name of opaque<V>") {
        opaque[V].asUtf8String.name shouldBe "opaque<V>"
      }
    }
  }
})
