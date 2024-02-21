package com.github.traderjoe95.mls.protocol.crypto.impl

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.protocol.crypto.Sign
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.Signature.Companion.asSignature
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
import org.bouncycastle.crypto.Signer
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
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
    signatureKey: SigningKey,
    content: ByteArray,
  ): Signature =
    signer().apply {
      init(true, signatureKey.asParameter)
      update(content, 0, content.size)
    }.generateSignature().asSignature

  context(Raise<SignatureError>)
  override fun verify(
    verificationKey: VerificationKey,
    content: ByteArray,
    signature: Signature,
  ) {
    val valid =
      signer().apply {
        init(false, DecoderError.wrap { verificationKey.asParameter })
        update(content, 0, content.size)
      }.verifySignature(signature.value)

    if (!valid) raise(SignatureError.BadSignature)
  }

  override fun generateSignatureKeyPair(): Pair<SigningKey, VerificationKey> =
    kpg().generateKeyPair().run { SigningKey(private.bytes) to VerificationKey(public.bytes) }

  override fun calculateVerificationKey(signingKey: SigningKey): VerificationKey =
    when (val p = signingKey.asParameter) {
      is Ed25519PrivateKeyParameters -> VerificationKey(p.generatePublicKey().bytes)
      is Ed448PrivateKeyParameters -> VerificationKey(p.generatePublicKey().bytes)
      is ECPrivateKeyParameters ->
        VerificationKey(
          ECPublicKeyParameters(p.parameters.g.multiply(p.d), p.parameters).bytes,
        )
      else -> error("Unsupported")
    }

  private fun signer(): Signer =
    when (dhKem) {
      DhKem.X25519_SHA256 -> Ed25519Signer()
      DhKem.X448_SHA512 -> Ed448Signer(byteArrayOf())
      else -> DSADigestSigner(ECDSASigner(), dhKem.hash.createDigest())
    }

  private fun kpg(): AsymmetricCipherKeyPairGenerator =
    when (dhKem) {
      DhKem.P256_SHA256 -> ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(secp256r1, rand)) }
      DhKem.P384_SHA384 -> ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(secp384r1, rand)) }
      DhKem.P521_SHA512 -> ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(secp521r1, rand)) }
      DhKem.X25519_SHA256 -> Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(rand)) }
      DhKem.X448_SHA512 -> Ed448KeyPairGenerator().apply { init(Ed448KeyGenerationParameters(rand)) }
    }

  private val secp256r1: ECNamedDomainParameters by lazy {
    ECNamedCurveTable.getOID("secp256r1").let { oid ->
      ECNamedDomainParameters(
        oid,
        ECNamedCurveTable.getByOID(oid),
      )
    }
  }

  private val secp384r1: ECNamedDomainParameters by lazy {
    ECNamedCurveTable.getOID("secp384r1").let { oid ->
      ECNamedDomainParameters(
        oid,
        ECNamedCurveTable.getByOID(oid),
      )
    }
  }

  private val secp521r1: ECNamedDomainParameters by lazy {
    ECNamedCurveTable.getOID("secp521r1").let { oid ->
      ECNamedDomainParameters(
        oid,
        ECNamedCurveTable.getByOID(oid),
      )
    }
  }

  private val p256: ASN1ObjectIdentifier by lazy { ECNamedCurveTable.getOID("P-256") }
  private val p384: ASN1ObjectIdentifier by lazy { ECNamedCurveTable.getOID("P-384") }
  private val p521: ASN1ObjectIdentifier by lazy { ECNamedCurveTable.getOID("P-521") }

  private val AsymmetricKeyParameter.bytes: ByteArray
    get() =
      when (this) {
        is ECPublicKeyParameters ->
          when (val oid = (parameters as ECNamedDomainParameters).name) {
            p256 -> P256_POINT_T.encodeUnsafe(q)
            p384 -> P384_POINT_T.encodeUnsafe(q)
            p521 -> P521_POINT_T.encodeUnsafe(q)
            else -> error("Unsupported curve ${ECNamedCurveTable.getName(oid)}")
          }

        is ECPrivateKeyParameters -> d.toByteArray()

        is Ed25519PublicKeyParameters -> encoded
        is Ed25519PrivateKeyParameters -> encoded
        is Ed448PublicKeyParameters -> encoded
        is Ed448PrivateKeyParameters -> encoded
        else -> error("Unsupported")
      }

  private val SigningKey.asParameter: AsymmetricKeyParameter
    get() =
      when (dhKem) {
        DhKem.P256_SHA256 -> ECPrivateKeyParameters(BigInteger(key), secp256r1)
        DhKem.P384_SHA384 -> ECPrivateKeyParameters(BigInteger(key), secp384r1)
        DhKem.P521_SHA512 -> ECPrivateKeyParameters(BigInteger(key), secp521r1)

        DhKem.X25519_SHA256 -> Ed25519PrivateKeyParameters(key)
        DhKem.X448_SHA512 -> Ed448PrivateKeyParameters(key)
      }

  context(Raise<BaseDecoderError>)
  private val VerificationKey.asParameter: AsymmetricKeyParameter
    get() =
      when (dhKem) {
        DhKem.P256_SHA256 -> ECPublicKeyParameters(key.decodeAs(P256_POINT_T), secp256r1)
        DhKem.P384_SHA384 -> ECPublicKeyParameters(key.decodeAs(P384_POINT_T), secp384r1)
        DhKem.P521_SHA512 -> ECPublicKeyParameters(key.decodeAs(P521_POINT_T), secp521r1)

        DhKem.X25519_SHA256 -> Ed25519PublicKeyParameters(key)
        DhKem.X448_SHA512 -> Ed448PublicKeyParameters(key)
      }
}
