package com.github.traderjoe95.mls.codec.util

import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.SliceError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.uIntRange
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class SliceTest : ShouldSpec({
  context("ByteArray.full") {
    should("return a slice covering the entire array") {
      checkAll(Arb.byteArray(1..1024)) { bytes ->
        bytes.full.also {
          it.data shouldBe bytes
          it.firstIndex shouldBe 0U
          it.lastIndex shouldBe bytes.uSize - 1U
          it.size shouldBe bytes.uSize
          it.hasRemaining shouldBe bytes.isNotEmpty()
        }
      }
    }
  }

  context("ByteArray.partial(range)") {
    should("return a slice covering the indicated range of the array, if start and end are in bounds") {
      checkAll(
        Arb.byteArray(4..1024).flatMap { bytes ->
          Arb.uIntRange(1U..<bytes.uSize / 2U, bytes.uSize / 2U..<bytes.uSize).map { it to bytes }
        },
      ) { (indices, bytes) ->
        shouldNotRaise { bytes.partial(indices) }.also {
          it.data shouldBe bytes.sliceArray(indices.toIntRange())
          it.firstIndex shouldBe indices.first
          it.lastIndex shouldBe indices.last
          it.size shouldBe (indices.last - indices.first + 1U)
          it.hasRemaining shouldBe true
        }
      }
    }

    should("return an empty slice when passing an empty range") {
      checkAll(Arb.byteArray(1..1024), Arb.uIntRange(1U..UInt.MAX_VALUE, 0U..0U, allowEmpty = true)) { bytes, indices ->
        shouldNotRaise { bytes.partial(indices) }.also {
          it.data shouldBe byteArrayOf()
          it.firstIndex shouldBe indices.first
          it.lastIndex shouldBe 0U
          it.size shouldBe 0U
          it.hasRemaining shouldBe false
        }
      }
    }

    should("raise an error when the start index of the range is out of bounds") {
      checkAll(
        Arb.byteArray(1..512).flatMap { bytes ->
          Arb.uIntRange((bytes.uSize + 1U)..<768U, 768U..1024U).map { it to bytes }
        },
      ) { (indices, bytes) ->
        shouldRaise<SliceError.IndexOutOfBounds> {
          bytes.partial(indices)
        } shouldBe SliceError.IndexOutOfBounds(bytes.uSize, indices.first)
      }
    }

    should("raise an error when the end index of the range is out of bounds") {
      checkAll(
        Arb.byteArray(1..512).flatMap { bytes ->
          Arb.uIntRange(0U..<bytes.uSize, bytes.uSize..1024U).map { it to bytes }
        },
      ) { (indices, bytes) ->
        shouldRaise<SliceError.IndexOutOfBounds> {
          bytes.partial(indices)
        } shouldBe SliceError.IndexOutOfBounds(bytes.uSize, indices.last)
      }
    }
  }

  context("ByteArray.partial(startIdx)") {
    should("return a slice covering from startIdx to the end of the array, if start is bounds") {
      checkAll(
        Arb.byteArray(4..1024).flatMap { bytes ->
          Arb.uInt(1U..<bytes.uSize).map { it to bytes }
        },
      ) { (startIdx, bytes) ->
        shouldNotRaise { bytes.partial(startIdx) }.also {
          it.data shouldBe bytes.sliceArray(startIdx.toInt()..<bytes.size)
          it.firstIndex shouldBe startIdx
          it.lastIndex shouldBe bytes.uSize - 1U
          it.size shouldBe bytes.uSize - startIdx
          it.hasRemaining shouldBe true
        }
      }
    }

    should("raise an error when the start index is out of bounds") {
      checkAll(
        Arb.byteArray(1..512).flatMap { bytes ->
          Arb.uInt((bytes.uSize + 1U)..1024U).map { it to bytes }
        },
      ) { (startIdx, bytes) ->
        shouldRaise<SliceError.IndexOutOfBounds> {
          bytes.partial(startIdx)
        } shouldBe SliceError.IndexOutOfBounds(bytes.uSize, startIdx)
      }
    }
  }

  context("Slice.get(i)") {
    should("return the ith byte, counting from the start of the slice, if it exists") {
      checkAll(
        Arb.byteArray(1..1024).flatMap { bytes ->
          Arb.slice(bytes, alreadyConsumedLength = 0U..128U).map { bytes to it }
        },
      ) { (bytes, slice) ->
        for (i in 0U..<slice.size) {
          shouldNotRaise { slice[i] } shouldBe bytes[i.toInt()]
        }
      }
    }

    should("raise an error if the index is out of bounds wrt the slice's range") {
      checkAll(
        Arb.slice(Arb.byteArray(0..1024), alreadyConsumedLength = 0U..128U).flatMap { slice ->
          Arb.uInt(slice.size..2048U).map { slice to it }
        },
      ) { (slice, oob) ->
        shouldRaise<DecoderError.PrematureEndOfStream> {
          slice[oob]
        } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, oob + 1U, slice.size)
      }
    }
  }

  context("Slice.componentN() (N=1..8)") {
    should("return the Nth byte") {
      checkAll(
        Arb.byteArray(8..1024).flatMap { bytes ->
          Arb.slice(bytes, alreadyConsumedLength = 0U..128U).map { bytes to it }
        },
      ) { (bytes, slice) ->
        shouldNotRaise { slice.component1() } shouldBe bytes[0]
        shouldNotRaise { slice.component2() } shouldBe bytes[1]
        shouldNotRaise { slice.component3() } shouldBe bytes[2]
        shouldNotRaise { slice.component4() } shouldBe bytes[3]
        shouldNotRaise { slice.component5() } shouldBe bytes[4]
        shouldNotRaise { slice.component6() } shouldBe bytes[5]
        shouldNotRaise { slice.component7() } shouldBe bytes[6]
        shouldNotRaise { slice.component8() } shouldBe bytes[7]
      }
    }
  }
})
