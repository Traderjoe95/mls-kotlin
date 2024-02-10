package com.github.traderjoe95.mls.delivery.util

import io.vertx.core.impl.ContextInternal
import io.vertx.core.impl.future.PromiseInternal
import io.vertx.kotlin.coroutines.coAwait
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousFileChannel
import java.nio.channels.CompletionHandler

context(ContextInternal)
suspend fun AsynchronousFileChannel.read(
  target: ByteBuffer,
  position: ULong,
): Int =
  promise<Int>().also { p ->
    read(target, position.toLong(), null, PromiseCompletionHandler(p))
  }.future().coAwait()

context(ContextInternal)
suspend fun AsynchronousFileChannel.write(
  source: ByteBuffer,
  position: ULong,
): Int =
  promise<Int>().also { p ->
    write(source, position.toLong(), null, PromiseCompletionHandler(p))
  }.future().coAwait()

private class PromiseCompletionHandler<T>(private val promise: PromiseInternal<T>) : CompletionHandler<T, Any?> {
  override fun completed(
    result: T,
    attachment: Any?,
  ) {
    promise.tryComplete(result)
  }

  override fun failed(
    exc: Throwable,
    attachment: Any?,
  ) {
    promise.tryFail(exc)
  }
}
