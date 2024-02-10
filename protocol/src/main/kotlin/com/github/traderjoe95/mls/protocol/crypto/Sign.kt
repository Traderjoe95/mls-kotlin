package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.types.crypto.SignContent
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

interface Sign {
  context(Raise<BaseEncoderError>)
  fun signWithLabel(
    signatureKey: SigningKey,
    label: String,
    content: ByteArray,
  ): Signature

  context(Raise<SignatureError>)
  fun verifyWithLabel(
    verificationKey: VerificationKey,
    label: String,
    content: ByteArray,
    signature: Signature,
  )

  context(Raise<BaseEncoderError>)
  fun generateSignatureKeyPair(): Pair<SigningKey, VerificationKey>

  context(Raise<BaseEncoderError>)
  fun calculateVerificationKey(signingKey: SigningKey): VerificationKey

  abstract class Provider : Sign {
    context(Raise<BaseEncoderError>)
    final override fun signWithLabel(
      signatureKey: SigningKey,
      label: String,
      content: ByteArray,
    ): Signature = sign(signatureKey, SignContent.create(label, content))

    context(Raise<SignatureError>)
    final override fun verifyWithLabel(
      verificationKey: VerificationKey,
      label: String,
      content: ByteArray,
      signature: Signature,
    ) = verify(verificationKey, SignContent.create(label, content), signature)

    context(Raise<BaseEncoderError>)
    private fun sign(
      signatureKey: SigningKey,
      content: SignContent,
    ): Signature = sign(signatureKey, SignContent.T.encode(content))

    internal abstract fun sign(
      signatureKey: SigningKey,
      content: ByteArray,
    ): Signature

    context(Raise<SignatureError>)
    private fun verify(
      verificationKey: VerificationKey,
      content: SignContent,
      signature: Signature,
    ) = verify(
      verificationKey,
      EncoderError.wrap { SignContent.T.encode(content) },
      signature,
    )

    context(Raise<SignatureError>)
    internal abstract fun verify(
      verificationKey: VerificationKey,
      content: ByteArray,
      signature: Signature,
    )
  }
}
