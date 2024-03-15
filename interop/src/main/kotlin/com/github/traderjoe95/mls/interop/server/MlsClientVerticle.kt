package com.github.traderjoe95.mls.interop.server

import com.github.traderjoe95.mls.interop.MlsClientImpl
import io.vertx.grpc.server.GrpcServer
import io.vertx.kotlin.core.http.httpServerOptionsOf
import io.vertx.kotlin.coroutines.CoroutineVerticle
import io.vertx.kotlin.coroutines.coAwait

class MlsClientVerticle : CoroutineVerticle() {
  override suspend fun start() {
    val grpcServer = GrpcServer.server(vertx)
    val service = MlsClientImpl(vertx)

    service.bindAll(grpcServer)

    vertx
      .createHttpServer(httpServerOptionsOf(compressionSupported = true, port = 8080))
      .requestHandler(grpcServer)
      .listen()
      .coAwait()
  }
}
