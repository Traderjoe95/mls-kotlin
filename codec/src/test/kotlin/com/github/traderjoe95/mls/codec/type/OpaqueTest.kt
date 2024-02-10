package com.github.traderjoe95.mls.codec.type

import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.byteArrayWithV
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.type.DataType.Companion.done
import com.github.traderjoe95.mls.codec.uIntRange
import com.github.traderjoe95.mls.codec.util.full
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.util.toIntRange
import com.github.traderjoe95.mls.codec.util.uSize
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class OpaqueTest : ShouldSpec({
  context("opaque[fixed]") {
    should("encode byte arrays of the correct length as themselves") {
      checkAll(Arb.byteArray(0..1024)) {
        shouldNotRaise { opaque[it.uSize].encode(it) shouldBe it }
      }
    }

    should("decode previously encoded byte arrays of the correct length") {
      checkAll(Arb.byteArray(0..1024)) {
        val t = opaque[it.uSize]
        shouldNotRaise {
          t.decode(t.encode(it).full).done() shouldBe it
        }
      }
    }

    context("when decoding") {
      should("consume all remaining bytes when their number is the fixed length") {
        checkAll(
          Arb.byteArray(0..1024).flatMap { bytes ->
            Arb.slice(
              bytes,
              alreadyConsumedLength = 0U..128U,
            ).map { it to bytes }
          },
        ) { (slice, bytes) ->
          shouldNotRaise { opaque[bytes.uSize].decode(slice).done() shouldBe bytes }
        }
      }

      should("only consume fixed bytes if there are more remaining") {
        checkAll(
          Arb.byteArray(0..1024).flatMap { bytes ->
            Arb.slice(
              bytes,
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { it to bytes }
          },
        ) { (slice, bytes) ->
          shouldNotRaise {
            opaque[bytes.uSize].decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.size shouldBe slice.size - bytes.uSize

              decoded shouldBe bytes
            }
          }
        }
      }

      should("raise an error when there are less bytes remaining than expected") {
        checkAll(
          Arb.pair(
            Arb.byteArray(0..1024),
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
            opaque[size].decode(slice)
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
        Arb.pair(Arb.byteArray(0..1024), Arb.uInt()).filter {
          it.first.uSize != it.second
        },
      ) { (bytes, fixed) ->
        shouldRaise<EncoderError.BadLength> { opaque[fixed].encode(bytes) }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of fixed") {
        checkAll(Arb.uInt()) {
          opaque[it].encodedLength shouldBe it
        }
      }

      should("have a name of opaque[fixed]") {
        checkAll(Arb.uInt()) {
          opaque[it].name shouldBe "opaque[$it]"
        }
      }
    }
  }

  context("opaque<min..max>") {
    should("encode byte arrays of the correct length as a length field plus themselves") {
      checkAll(
        Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
          it.first != it.last
        }.flatMap { range ->
          Arb.byteArray(range.toIntRange()).map { it to range }
        },
      ) { (bytes, range) ->
        shouldNotRaise {
          opaque[range].encode(bytes) shouldBe byteArrayOf(bytes.uSize.toByte(), *bytes)
        }
      }
    }

    should("decode previously encoded byte arrays of the correct length") {
      checkAll(
        Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
          it.first != it.last
        }.flatMap { range ->
          Arb.byteArray(range.toIntRange()).map { it to range }
        },
      ) { (bytes, range) ->
        val t = throwAnyError { opaque[range] }
        shouldNotRaise {
          t.decode(t.encode(bytes).full).done() shouldBe bytes
        }
      }
    }

    context("when decoding") {
      should("consume all remaining bytes when their number corresponds to the length field") {
        checkAll(
          Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
            it.first != it.last
          }.flatMap { range ->
            Arb.byteArray(range.toIntRange()).flatMap { bytes ->
              Arb.slice(
                byteArrayOf(bytes.size.toByte(), *bytes),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, bytes, range) }
            }
          },
        ) { (slice, bytes, range) ->
          shouldNotRaise {
            opaque[range].decode(slice).done() shouldBe bytes
          }
        }
      }

      should("only consume bytes according to the length field if there are more remaining") {
        checkAll(
          Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter {
            it.first != it.last
          }.flatMap { range ->
            Arb.byteArray(range.toIntRange()).flatMap { bytes ->
              Arb.slice(
                byteArrayOf(bytes.size.toByte(), *bytes),
                alreadyConsumedLength = 0U..128U,
                extraLength = 1U..128U,
              ).map { Triple(it, bytes, range) }
            }
          },
        ) { (slice, bytes, range) ->
          shouldNotRaise {
            opaque[range].decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.size shouldBe slice.size - bytes.uSize - 1U

              decoded shouldBe bytes
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
              Arb.byteArray(range.toIntRange()),
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
            opaque[range].decode(slice)
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
          Arb.byteArray(0..255),
          Arb.uIntRange(Arb.uInt(0U..254U), Arb.uInt(1U..255U)).filter { it.first != it.last },
        ).filter {
          it.first.uSize !in it.second
        },
      ) { (bytes, range) ->
        shouldRaise<EncoderError.BadLength> { opaque[range].encode(bytes) }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have no encodedLength") {
        checkAll(Arb.uIntRange(0x0U..0x7FFFFFFFU, 0x80000000U..0xFFFFFFFFU)) {
          shouldNotRaise { opaque[it] }.encodedLength.shouldBeNull()
        }
      }

      should("have a name of opaque<min..max>") {
        checkAll(Arb.uIntRange(0x0U..0x7FFFFFFFU, 0x80000000U..0xFFFFFFFFU)) {
          shouldNotRaise { opaque[it] }.name shouldBe "opaque<${it.first}..${it.last}>"
        }
      }
    }
  }

  context("opaque<V>") {
    should("encode byte arrays of any length less than 0x00FFFFFF") {
      checkAll(
        Arb.byteArray(0..1024),
      ) { bytes ->
        shouldNotRaise {
          opaque[V].encode(bytes) shouldBe byteArrayOf(*V(uint8).encode(bytes.uSize), *bytes)
        }
      }
    }

    should("decode previously encoded byte arrays of the correct length") {
      checkAll(
        Arb.byteArray(0..1024),
      ) { bytes ->
        val t = opaque[V]
        shouldNotRaise {
          t.decode(t.encode(bytes).full).done() shouldBe bytes
        }
      }
    }

    context("when decoding") {
      should("consume all remaining bytes when their number corresponds to the length field") {
        checkAll(
          Arb.byteArrayWithV(Arb.int(0..1024)).flatMap { (bytesWithV, bytes, _) ->
            Arb.slice(
              bytesWithV,
              alreadyConsumedLength = 0U..128U,
            ).map { it to bytes }
          },
        ) { (slice, bytes) ->
          shouldNotRaise {
            opaque[V].decode(slice).done() shouldBe bytes
          }
        }
      }

      should("only consume bytes according to the length field if there are more remaining") {
        checkAll(
          Arb.byteArrayWithV(Arb.int(0..1024)).flatMap { (bytesWithV, bytes, size) ->
            Arb.slice(
              bytesWithV,
              alreadyConsumedLength = 0U..128U,
              extraLength = 1U..128U,
            ).map { Triple(it, bytes, size) }
          },
        ) { (slice, bytes, size) ->
          shouldNotRaise {
            opaque[V].decode(slice).also { (decoded, remaining) ->
              remaining.hasRemaining shouldBe true
              remaining.size shouldBe slice.size - size - V(uint8).encode(size).uSize

              decoded shouldBe bytes
            }
          }
        }
      }

      should("raise an error when there are less bytes remaining than the length tag indicates") {
        checkAll(
          Arb.pair(
            Arb.byteArray(0..1023),
            Arb.uInt(1U..1024U),
          ).filter {
            it.first.uSize < it.second
          }.flatMap { (bytes, size) ->
            Arb.slice(
              throwAnyError { byteArrayOf(*V(uint8).encode(size), *bytes) },
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..(size - bytes.uSize - 1U),
            ).map { it to size }
          },
        ) { (slice, size) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            opaque[V].decode(slice)
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
        opaque[V].encodedLength.shouldBeNull()
      }

      should("have a name of opaque<V>") {
        opaque[V].name shouldBe "opaque<V>"
      }
    }
  }
})
