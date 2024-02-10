package com.github.traderjoe95.mls.codec

import com.github.traderjoe95.mls.codec.testing.anyStruct1
import com.github.traderjoe95.mls.codec.testing.anyStruct2
import com.github.traderjoe95.mls.codec.testing.anyStruct3
import com.github.traderjoe95.mls.codec.testing.anyStruct4
import com.github.traderjoe95.mls.codec.testing.anyStruct5
import com.github.traderjoe95.mls.codec.testing.anyStruct6
import com.github.traderjoe95.mls.codec.testing.anyStruct7
import com.github.traderjoe95.mls.codec.testing.anyStruct8
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.checkAll

class StructTest : ShouldSpec({
  context("Struct1") {
    context("size") {
      should("be 1") {
        checkAll(Arb.anyStruct1()) {
          it.size shouldBe 1U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct1()) {
          it.fields.shouldContainExactly(it.field1)
        }
      }

      context("get") {
        should("should return the correct fields") {
          checkAll(Arb.anyStruct1()) {
            it[0U] shouldBe it.field1
          }
        }
      }
    }
  }

  context("Struct2") {
    context("size") {
      should("be 2") {
        checkAll(Arb.anyStruct2()) {
          it.size shouldBe 2U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct2()) {
          it.fields.shouldContainExactly(it.field1, it.field2)
        }
      }
    }

    context("get") {
      should("should return the correct fields") {
        checkAll(Arb.anyStruct2()) {
          it[0U] shouldBe it.field1
          it[1U] shouldBe it.field2
        }
      }
    }
  }

  context("Struct3") {
    context("size") {
      should("be 3") {
        checkAll(Arb.anyStruct3()) {
          it.size shouldBe 3U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct3()) {
          it.fields.shouldContainExactly(it.field1, it.field2, it.field3)
        }
      }
    }

    context("get") {
      should("should return the correct fields") {
        checkAll(Arb.anyStruct3()) {
          it[0U] shouldBe it.field1
          it[1U] shouldBe it.field2
          it[2U] shouldBe it.field3
        }
      }
    }
  }

  context("Struct4") {
    context("size") {
      should("be 4") {
        checkAll(Arb.anyStruct4()) {
          it.size shouldBe 4U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct4()) {
          it.fields.shouldContainExactly(it.field1, it.field2, it.field3, it.field4)
        }
      }
    }

    context("get") {
      should("should return the correct fields") {
        checkAll(Arb.anyStruct4()) {
          it[0U] shouldBe it.field1
          it[1U] shouldBe it.field2
          it[2U] shouldBe it.field3
          it[3U] shouldBe it.field4
        }
      }
    }
  }

  context("Struct5") {
    context("size") {
      should("be 5") {
        checkAll(Arb.anyStruct5()) {
          it.size shouldBe 5U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct5()) {
          it.fields.shouldContainExactly(it.field1, it.field2, it.field3, it.field4, it.field5)
        }
      }
    }

    context("get") {
      should("should return the correct fields") {
        checkAll(Arb.anyStruct5()) {
          it[0U] shouldBe it.field1
          it[1U] shouldBe it.field2
          it[2U] shouldBe it.field3
          it[3U] shouldBe it.field4
          it[4U] shouldBe it.field5
        }
      }
    }
  }

  context("Struct6") {
    context("size") {
      should("be 6") {
        checkAll(Arb.anyStruct6()) {
          it.size shouldBe 6U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct6()) {
          it.fields.shouldContainExactly(it.field1, it.field2, it.field3, it.field4, it.field5, it.field6)
        }
      }
    }

    context("get") {
      should("should return the correct fields") {
        checkAll(Arb.anyStruct6()) {
          it[0U] shouldBe it.field1
          it[1U] shouldBe it.field2
          it[2U] shouldBe it.field3
          it[3U] shouldBe it.field4
          it[4U] shouldBe it.field5
          it[5U] shouldBe it.field6
        }
      }
    }
  }

  context("Struct7") {
    context("size") {
      should("be 7") {
        checkAll(Arb.anyStruct7()) {
          it.size shouldBe 7U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct7()) {
          it.fields.shouldContainExactly(it.field1, it.field2, it.field3, it.field4, it.field5, it.field6, it.field7)
        }
      }
    }

    context("get") {
      should("should return the correct fields") {
        checkAll(Arb.anyStruct7()) {
          it[0U] shouldBe it.field1
          it[1U] shouldBe it.field2
          it[2U] shouldBe it.field3
          it[3U] shouldBe it.field4
          it[4U] shouldBe it.field5
          it[5U] shouldBe it.field6
          it[6U] shouldBe it.field7
        }
      }
    }
  }

  context("Struct8") {
    context("size") {
      should("be 8") {
        checkAll(Arb.anyStruct8()) {
          it.size shouldBe 8U
        }
      }
    }

    context("fields") {
      should("contain the fields in order") {
        checkAll(Arb.anyStruct8()) {
          it.fields.shouldContainExactly(
            it.field1,
            it.field2,
            it.field3,
            it.field4,
            it.field5,
            it.field6,
            it.field7,
            it.field8,
          )
        }
      }
    }

    context("get") {
      should("should return the correct fields") {
        checkAll(Arb.anyStruct8()) {
          it[0U] shouldBe it.field1
          it[1U] shouldBe it.field2
          it[2U] shouldBe it.field3
          it[3U] shouldBe it.field4
          it[4U] shouldBe it.field5
          it[5U] shouldBe it.field6
          it[6U] shouldBe it.field7
          it[7U] shouldBe it.field8
        }
      }
    }
  }
})
