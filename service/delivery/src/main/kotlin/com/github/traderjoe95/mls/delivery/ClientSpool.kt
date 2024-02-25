package com.github.traderjoe95.mls.delivery

import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.delivery.util.read
import com.github.traderjoe95.mls.delivery.util.write
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.ULID.Companion.toULID
import io.vertx.core.Closeable
import io.vertx.core.Handler
import io.vertx.core.Promise
import io.vertx.core.impl.ContextInternal
import io.vertx.core.impl.VertxInternal
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousFileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import kotlin.properties.Delegates

sealed class ClientSpool(
  val clientId: ULID,
) : Handler<Pair<ULID, MlsMessage<*>>>

internal class FileBackedSpool(
  private val vertx: VertxInternal,
  clientId: ULID,
  private val persistenceDir: Path,
) : ClientSpool(clientId),
  Closeable,
  CoroutineScope by CoroutineScope(vertx.dispatcher() + SupervisorJob()),
  ContextInternal by vertx.context {
  private lateinit var channel: AsynchronousFileChannel

  private val filePath: Path = persistenceDir.resolve("$clientId.spool")
  private var readPosition: ULong = 0UL
  private var writePosition by Delegates.notNull<ULong>()

  private val readBuffer: ByteBuffer = ByteBuffer.allocateDirect(4096)
  private val writeBuffer: ByteBuffer = ByteBuffer.allocateDirect(4096)

  companion object {
    const val MAGIC_NUMBER = 0x21091995
  }

  private fun openChannel(): AsynchronousFileChannel =
    AsynchronousFileChannel.open(
      filePath,
      setOf(StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.DSYNC),
      vertx.workerPool.executor(),
    )

  private suspend fun open() {
    vertx.fileSystem().mkdirs(persistenceDir.toString()).coAwait()

    channel = vertx.executeBlocking(::openChannel).coAwait()
    writePosition = vertx.executeBlocking(channel::size).coAwait().toULong()
  }

  override fun handle(event: Pair<ULID, MlsMessage<*>>) {
    launch {
      if (!::channel.isInitialized.not()) open()

      val (id, message) = event

      writeBuffer.clear()

      val encoded = throwAnyError { MlsMessage.dataT.encode(message) }
      var remaining = encoded.size

      writeBuffer.putInt(MAGIC_NUMBER)
      writeBuffer.putInt(remaining)
      writeBuffer.put(id.toBytes())

      while (remaining > 0) {
        writeBuffer.compact()

        val bytesToTransfer = minOf(remaining, writeBuffer.remaining())
        writeBuffer.put(encoded, encoded.size - remaining, bytesToTransfer)
        remaining -= bytesToTransfer

        val bytesWritten = channel.write(writeBuffer.flip(), writePosition)
        writePosition += bytesWritten.toUInt()
      }
    }
  }

  @Suppress("kotlin:S6508")
  override fun close(completion: Promise<Void>?) {
    if (::channel.isInitialized) channel.close()
    completion?.complete()
  }

  private suspend fun readHeader(): Pair<Int, ULID>? {
    if (readBuffer.remaining() < 24 && 24 - readBuffer.remaining() > readFromFile()) return null

    assert(readBuffer.getInt() == MAGIC_NUMBER)
    return readBuffer.getInt() to ByteArray(16).also(readBuffer::get).toULID().getOrNull()!!
  }

  private suspend fun readItem(): ByteArray? =
    readHeader()?.let { (length, _) ->
      if (readBuffer.remaining() < length && readFromFile() < 0) return null

      ByteArray(length).also { result ->
        var read = 0

        while (read < length) {
          readBuffer.get(result, read, length - read)

          if (read + readBuffer.remaining() < length) {
            read += readBuffer.remaining()
            assert(readFromFile() > 0)
          }
        }
      }
    }

  private suspend fun readFromFile(): Int {
    val bytesRead = channel.read(readBuffer.compact(), readPosition)
    if (bytesRead > 0) readPosition += bytesRead.toUInt()
    readBuffer.flip()
    return bytesRead
  }
}
