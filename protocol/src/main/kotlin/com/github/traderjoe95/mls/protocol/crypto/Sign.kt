package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.types.crypto.SignContent
import com.github.traderjoe95.mls.protocol.types.crypto.SignContent.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey

interface Sign {
  fun signWithLabel(
    signatureKey: SignaturePrivateKey,
    label: String,
    content: ByteArray,
  ): Signature

  context(Raise<SignatureError>)
  fun verifyWithLabel(
    signaturePublicKey: SignaturePublicKey,
    label: String,
    content: ByteArray,
    signature: Signature,
  )

  fun generateSignatureKeyPair(): SignatureKeyPair

  fun reconstructPublicKey(privateKey: SignaturePrivateKey): SignatureKeyPair

  abstract class Provider : Sign {
    final override fun signWithLabel(
      signatureKey: SignaturePrivateKey,
      label: String,
      content: ByteArray,
    ): Signature = sign(signatureKey, SignContent.create(label, content))

    context(Raise<SignatureError>)
    final override fun verifyWithLabel(
      signaturePublicKey: SignaturePublicKey,
      label: String,
      content: ByteArray,
      signature: Signature,
    ) = verify(signaturePublicKey, SignContent.create(label, content), signature)

    private fun sign(
      signatureKey: SignaturePrivateKey,
      content: SignContent,
    ): Signature = sign(signatureKey, content.encodeUnsafe())

    internal abstract fun sign(
      signatureKey: SignaturePrivateKey,
      content: ByteArray,
    ): Signature

    context(Raise<SignatureError>)
    private fun verify(
      signaturePublicKey: SignaturePublicKey,
      content: SignContent,
      signature: Signature,
    ): Unit =
      verify(
        signaturePublicKey,
        content.encodeUnsafe(),
        signature,
      )

    context(Raise<SignatureError>)
    internal abstract fun verify(
      signaturePublicKey: SignaturePublicKey,
      content: ByteArray,
      signature: Signature,
    )
  }
}
