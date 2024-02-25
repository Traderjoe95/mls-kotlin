package com.github.traderjoe95.mls.protocol.crypto.impl

import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.protocol.crypto.Auth
import com.github.traderjoe95.mls.protocol.crypto.Kdf
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Mac.Companion.asMac
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.util.Arrays

internal class Hkdf(private val hash: HashFunction) : Kdf.Provider(), Auth {
  companion object {
    const val VERSION_LABEL = "HPKE-v1"
  }

  override val hashLen: UShort
    get() = hash.hashLen

  internal fun labeledExtract(
    salt: ByteArray?,
    suiteId: ByteArray,
    label: String,
    ikm: ByteArray,
  ): ByteArray =
    extract(
      salt ?: ByteArray(hashLen.toInt()),
      Arrays.concatenate(VERSION_LABEL.encodeToByteArray(), suiteId, label.encodeToByteArray(), ikm).asSecret,
    ).bytes

  internal fun labeledExpand(
    prk: ByteArray,
    suiteId: ByteArray,
    label: String,
    info: ByteArray?,
    length: UShort,
  ): ByteArray {
    val labeledInfo =
      ByteArray(2 + VERSION_LABEL.length + suiteId.size + label.length + (info?.size ?: 0)).also {
        uint16(length).encode().copyInto(it)
        VERSION_LABEL.encodeToByteArray().copyInto(it, destinationOffset = 2)
        suiteId.copyInto(it, destinationOffset = 2 + VERSION_LABEL.length)
        label.encodeToByteArray().copyInto(it, destinationOffset = 2 + VERSION_LABEL.length + suiteId.size)
        info?.copyInto(it, destinationOffset = 2 + VERSION_LABEL.length + suiteId.size + label.length)
      }

    return expand(prk.asSecret, labeledInfo, length).bytes
  }

  override fun extract(
    salt: ByteArray,
    ikm: Secret,
  ): Secret =
    ByteArray(hash.hashLen.toInt()).also { out ->
      hmac().apply {
        init(KeyParameter(salt))
        update(ikm.bytes, 0, ikm.bytes.size)
      }.doFinal(out, 0)
    }.asSecret

  override fun expand(
    prk: Secret,
    info: ByteArray,
    length: UShort,
  ): Secret {
    val out = ByteArray(length.toInt())
    val hmac = hmac().apply { init(KeyParameter(prk.bytes)) }
    val n = if (length % hash.hashLen == 0U) length / hash.hashLen else length / hash.hashLen + 1U

    for (i in 0U..<n) {
      val ti = ByteArray(hash.hashLen.toInt())

      hmac.apply {
        if (i >= 1U) update(out, ((i - 1U) * hash.hashLen).toInt(), hash.hashLen.toInt())

        update(info, 0, info.size)
        update((i + 1U).toByte())
      }.doFinal(ti, 0)
      hmac.reset()

      ti.copyInto(
        out,
        (i * hash.hashLen).toInt(),
        0,
        if (i < n - 1U) {
          hash.hashLen.toInt()
        } else {
          out.size - (i * hash.hashLen).toInt()
        },
      )
    }

    return out.asSecret
  }

  override fun mac(
    secret: Secret,
    content: ByteArray,
  ): Mac =
    ByteArray(hashLen.toInt()).also { out ->
      hmac().apply {
        init(KeyParameter(secret.bytes))
        update(content, 0, content.size)
        doFinal(out, 0)
      }
    }.asMac

  private fun hmac(): HMac = HMac(hash.createDigest())
}
