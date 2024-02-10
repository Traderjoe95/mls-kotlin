package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.protocol.types.crypto.KdfLabel
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface Kdf {
  context(Raise<EncoderError>)
  fun expandWithLabel(
    secret: Secret,
    label: String,
    context: ByteArray,
    length: UShort = hashLen,
  ): Secret

  context(Raise<EncoderError>)
  fun expandWithLabel(
    secret: Secret,
    label: String,
    context: String,
    length: UShort = hashLen,
  ): Secret

  context(Raise<EncoderError>)
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
  ): Secret = extract(salt.key, ikm)

  val hashLen: UShort

  abstract class Provider : Kdf {
    context(Raise<EncoderError>)
    final override fun expandWithLabel(
      secret: Secret,
      label: String,
      context: ByteArray,
      length: UShort,
    ): Secret = expand(secret, KdfLabel.create(length, label, context), length)

    context(Raise<EncoderError>)
    final override fun expandWithLabel(
      secret: Secret,
      label: String,
      context: String,
      length: UShort,
    ): Secret = expandWithLabel(secret, label, context.encodeToByteArray(), length)

    context(Raise<EncoderError>)
    final override fun deriveSecret(
      secret: Secret,
      label: String,
    ): Secret = expandWithLabel(secret, label, byteArrayOf())

    context(Raise<EncoderError>)
    private fun expand(
      secret: Secret,
      kdfLabel: KdfLabel,
      length: UShort,
    ): Secret = expand(secret, KdfLabel.T.encode(kdfLabel), length)

    internal abstract fun expand(
      prk: Secret,
      info: ByteArray,
      length: UShort,
    ): Secret
  }
}
