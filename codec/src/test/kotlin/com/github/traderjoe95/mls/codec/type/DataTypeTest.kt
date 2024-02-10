package com.github.traderjoe95.mls.codec.type

import com.github.traderjoe95.mls.codec.type.struct.struct
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe

class DataTypeTest : ShouldSpec({
  context("DataType.Named") {
    should("override the name property of the delegated data type") {
      uint8.named("Test").name shouldBe "Test"
      uint8[V].named("opaque<V>").name shouldBe "opaque<V>"
      optional[uint32].named("optionalUInt32").name shouldBe "optionalUInt32"
      struct("oldName") { it.field("test", uint8) }.named("newName").name shouldBe "newName"
    }
  }
})
