package com.github.traderjoe95.mls.protocol.testing

import io.kotest.core.spec.style.FunSpec
import io.vertx.core.Vertx
import io.vertx.kotlin.coroutines.coAwait

abstract class VertxFunSpec(body: FunSpec.(Vertx) -> Unit = {}) : FunSpec({
  val vertx = Vertx.vertx()
  afterSpec { vertx.close().coAwait() }

  body(vertx)
})
