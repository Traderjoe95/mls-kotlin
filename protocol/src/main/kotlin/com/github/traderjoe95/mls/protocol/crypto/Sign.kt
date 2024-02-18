package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.types.crypto.SignContent
import com.github.traderjoe95.mls.protocol.types.crypto.SignContent.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey

interface Sign {
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

  fun generateSignatureKeyPair(): Pair<SigningKey, VerificationKey>

  fun calculateVerificationKey(signingKey: SigningKey): VerificationKey

  abstract class Provider : Sign {
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

    private fun sign(
      signatureKey: SigningKey,
      content: SignContent,
    ): Signature = sign(signatureKey, content)

    internal abstract fun sign(
      signatureKey: SigningKey,
      content: ByteArray,
    ): Signature

    context(Raise<SignatureError>)
    private fun verify(
      verificationKey: VerificationKey,
      content: SignContent,
      signature: Signature,
    ): Unit =
      verify(
        verificationKey,
        content.encodeUnsafe(),
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
