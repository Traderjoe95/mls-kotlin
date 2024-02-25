package com.github.traderjoe95.mls.protocol.crypto.impl

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.Sign
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.Signature.Companion.asSignature
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.util.padStart
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
import org.bouncycastle.crypto.Signer
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters
import org.bouncycastle.crypto.signers.DSADigestSigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import java.math.BigInteger
import java.security.SecureRandom
import com.github.traderjoe95.mls.codec.error.DecoderError as BaseDecoderError

internal class SignProvider(
  private val dhKem: DhKem,
  private val rand: SecureRandom = SecureRandom(),
) : Sign.Provider() {
  override fun sign(
    signatureKey: SignaturePrivateKey,
    content: ByteArray,
  ): Signature =
    signer().apply {
      init(true, signatureKey.asParameter)
      update(content, 0, content.size)
    }.generateSignature().asSignature

  context(Raise<SignatureError>)
  override fun verify(
    signaturePublicKey: SignaturePublicKey,
    content: ByteArray,
    signature: Signature,
  ) {
    val valid =
      signer().apply {
        init(false, DecoderError.wrap { signaturePublicKey.asParameter })
        update(content, 0, content.size)
      }.verifySignature(signature.bytes)

    if (!valid) raise(SignatureError.BadSignature)
  }

  override fun generateSignatureKeyPair(): SignatureKeyPair =
    kpg.generateKeyPair().run {
      SignatureKeyPair(SignaturePrivateKey(private.bytes), SignaturePublicKey(public.bytes))
    }

  override fun reconstructPublicKey(privateKey: SignaturePrivateKey): SignatureKeyPair =
    SignatureKeyPair(
      privateKey,
      when (val p = privateKey.asParameter) {
        is Ed25519PrivateKeyParameters ->
          SignaturePublicKey(p.generatePublicKey().bytes)

        is Ed448PrivateKeyParameters -> SignaturePublicKey(p.generatePublicKey().bytes)
        is ECPrivateKeyParameters ->
          SignaturePublicKey(
            ECPublicKeyParameters(p.parameters.g.multiply(p.d), p.parameters).bytes,
          )

        else -> error("Unsupported")
      },
    )

  private fun signer(): Signer =
    when (dhKem) {
      DhKem.X25519_SHA256 -> Ed25519Signer()
      DhKem.X448_SHA512 -> Ed448Signer(byteArrayOf())
      else -> DSADigestSigner(ECDSASigner(), dhKem.hash.createDigest())
    }

  private val kpg: AsymmetricCipherKeyPairGenerator by lazy {
    when (dhKem) {
      DhKem.P256_SHA256, DhKem.P384_SHA384, DhKem.P521_SHA512 ->
        ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(dhKem.domainParams, rand)) }

      DhKem.X25519_SHA256 -> Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(rand)) }
      DhKem.X448_SHA512 -> Ed448KeyPairGenerator().apply { init(Ed448KeyGenerationParameters(rand)) }
    }
  }

  private val AsymmetricKeyParameter.bytes: ByteArray
    get() =
      when (this) {
        is ECPublicKeyParameters -> q.getEncoded(false)
        is ECPrivateKeyParameters -> d.toByteArray().padStart(dhKem.nsk.toUInt())

        is Ed25519PublicKeyParameters -> encoded
        is Ed25519PrivateKeyParameters -> encoded
        is Ed448PublicKeyParameters -> encoded
        is Ed448PrivateKeyParameters -> encoded
        else -> error("Unsupported")
      }

  private val SignaturePrivateKey.asParameter: AsymmetricKeyParameter
    get() =
      when (dhKem) {
        DhKem.P256_SHA256, DhKem.P384_SHA384, DhKem.P521_SHA512 ->
          ECPrivateKeyParameters(BigInteger(1, bytes), dhKem.domainParams)

        DhKem.X25519_SHA256 -> Ed25519PrivateKeyParameters(bytes)
        DhKem.X448_SHA512 -> Ed448PrivateKeyParameters(bytes)
      }

  context(Raise<BaseDecoderError>)
  private val SignaturePublicKey.asParameter: AsymmetricKeyParameter
    get() =
      when (dhKem) {
        DhKem.P256_SHA256, DhKem.P384_SHA384, DhKem.P521_SHA512 ->
          ECPublicKeyParameters(dhKem.domainParams.curve.decodePoint(bytes), dhKem.domainParams)

        DhKem.X25519_SHA256 -> Ed25519PublicKeyParameters(bytes)
        DhKem.X448_SHA512 -> Ed448PublicKeyParameters(bytes)
      }
}
