package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.error.CreateSignatureError
import com.github.traderjoe95.mls.protocol.error.ReconstructSignaturePublicKeyError
import com.github.traderjoe95.mls.protocol.error.VerifySignatureError
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
  ): Either<CreateSignatureError, Signature>

  fun verifyWithLabel(
    signaturePublicKey: SignaturePublicKey,
    label: String,
    content: ByteArray,
    signature: Signature,
  ): Either<VerifySignatureError, Unit>

  fun generateSignatureKeyPair(): SignatureKeyPair

  fun reconstructPublicKey(privateKey: SignaturePrivateKey): Either<ReconstructSignaturePublicKeyError, SignatureKeyPair>

  abstract class Provider : Sign {
    final override fun signWithLabel(
      signatureKey: SignaturePrivateKey,
      label: String,
      content: ByteArray,
    ): Either<CreateSignatureError, Signature> = sign(signatureKey, SignContent.create(label, content))

    final override fun verifyWithLabel(
      signaturePublicKey: SignaturePublicKey,
      label: String,
      content: ByteArray,
      signature: Signature,
    ): Either<VerifySignatureError, Unit> = verify(signaturePublicKey, SignContent.create(label, content), signature)

    private fun sign(
      signatureKey: SignaturePrivateKey,
      content: SignContent,
    ): Either<CreateSignatureError, Signature> = sign(signatureKey, content.encodeUnsafe())

    internal abstract fun sign(
      signatureKey: SignaturePrivateKey,
      content: ByteArray,
    ): Either<CreateSignatureError, Signature>

    private fun verify(
      signaturePublicKey: SignaturePublicKey,
      content: SignContent,
      signature: Signature,
    ): Either<VerifySignatureError, Unit> =
      verify(
        signaturePublicKey,
        content.encodeUnsafe(),
        signature,
      )

    internal abstract fun verify(
      signaturePublicKey: SignaturePublicKey,
      content: ByteArray,
      signature: Signature,
    ): Either<VerifySignatureError, Unit>
  }
}
