package com.github.traderjoe95.mls.protocol.interop

import io.vertx.core.json.JsonObject

interface TestVector {
  fun toJson(): JsonObject

  fun verify(): Boolean
}
