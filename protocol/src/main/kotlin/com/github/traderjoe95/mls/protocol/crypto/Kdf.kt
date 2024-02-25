package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.types.crypto.KdfLabel
import com.github.traderjoe95.mls.protocol.types.crypto.KdfLabel.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface Kdf {
  fun expandWithLabel(
    secret: Secret,
    label: String,
    context: ByteArray,
    length: UShort = hashLen,
  ): Secret

  fun expandWithLabel(
    secret: Secret,
    label: String,
    context: String,
    length: UShort = hashLen,
  ): Secret

  fun deriveSecret(
    secret: Secret,
    label: String,
  ): Secret

  fun extract(
    salt: ByteArray,
    ikm: Secret,
  ): Secret

  fun extract(
    salt: Secret,
    ikm: Secret,
  ): Secret = extract(salt.bytes, ikm)

  val hashLen: UShort

  abstract class Provider : Kdf {
    final override fun expandWithLabel(
      secret: Secret,
      label: String,
      context: ByteArray,
      length: UShort,
    ): Secret = expand(secret, KdfLabel.create(length, label, context), length)

    final override fun expandWithLabel(
      secret: Secret,
      label: String,
      context: String,
      length: UShort,
    ): Secret = expandWithLabel(secret, label, context.encodeToByteArray(), length)

    final override fun deriveSecret(
      secret: Secret,
      label: String,
    ): Secret = expandWithLabel(secret, label, byteArrayOf())

    private fun expand(
      secret: Secret,
      kdfLabel: KdfLabel,
      length: UShort,
    ): Secret = expand(secret, kdfLabel.encodeUnsafe(), length)

    internal abstract fun expand(
      prk: Secret,
      info: ByteArray,
      length: UShort,
    ): Secret
  }
}
