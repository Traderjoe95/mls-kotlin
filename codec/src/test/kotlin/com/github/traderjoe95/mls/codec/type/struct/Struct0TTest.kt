package com.github.traderjoe95.mls.codec.type.struct

import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.slice
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.alphanumeric
import io.kotest.property.arbitrary.of
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll

class Struct0TTest : ShouldSpec({
  context("Struct0T") {
    context(".encode(value)") {
      should("always return an empty array") {
        checkAll(Arb.of(Unit)) {
          shouldNotRaise { Struct0T.encode(null) } shouldBe byteArrayOf()
        }
      }
    }

    context(".decode(bytes)") {
      should("return null and not consume any bytes") {
        checkAll(Arb.slice(Arb.byteArray(0..1024), alreadyConsumedLength = 0U..128U)) {
          shouldNotRaise { Struct0T.decode(it) }.also { (decoded, remaining) ->
            remaining.firstIndex shouldBe it.firstIndex
            remaining.lastIndex shouldBe it.lastIndex

            decoded shouldBe null
          }
        }
      }
    }

    context(".create()") {
      should("always return null") {
        checkAll(Arb.of(Unit)) {
          Struct0T.create() shouldBe null
        }
      }
    }

    context(".name") {
      should("should be struct {}") {
        Struct0T.name shouldBe "struct {}"
      }
    }

    context(".toString()") {
      should("should be struct {}") {
        Struct0T.toString() shouldBe "struct {}"
      }
    }

    context(".encodedLength") {
      should("should be 0") {
        Struct0T.encodedLength shouldBe 0U
      }
    }

    context(".members") {
      should("should be empty") {
        Struct0T.members.shouldBeEmpty()
      }
    }

    context("get(fieldName)") {
      should("should always return null") {
        checkAll(Arb.string(1..32, Codepoint.alphanumeric())) {
          Struct0T[it].shouldBeNull()
        }
      }
    }
  }
})
