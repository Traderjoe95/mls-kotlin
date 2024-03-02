package com.github.traderjoe95.mls.protocol.crypto.impl

import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import org.bouncycastle.math.ec.WNafUtil
import java.math.BigInteger
import java.security.SecureRandom

internal enum class DhKem(val id: Short, val hash: HashFunction, private val curveName: String = "n/a") {
  P256_SHA256(HPKE.kem_P256_SHA256, HashFunction.SHA256, "P-256"),
  P384_SHA384(HPKE.kem_P384_SHA348, HashFunction.SHA384, "P-384"),
  P521_SHA512(HPKE.kem_P521_SHA512, HashFunction.SHA512, "P-521"),
  X25519_SHA256(HPKE.kem_X25519_SHA256, HashFunction.SHA256),
  X448_SHA512(HPKE.kem_X448_SHA512, HashFunction.SHA512),
  ;

  val nsk: UShort
    get() =
      when (this) {
        P256_SHA256 -> 32U
        P384_SHA384 -> 48U
        P521_SHA512 -> 66U
        X25519_SHA256 -> 32U
        X448_SHA512 -> 56U
      }

  private val bitmask: Byte
    get() =
      when (this) {
        P256_SHA256, P384_SHA384 -> 0xff.toByte()
        P521_SHA512 -> 0x01
        else -> 0
      }

  val domainParams: ECDomainParameters by lazy {
    when (this) {
      P256_SHA256, P384_SHA384, P521_SHA512 ->
        ECNamedCurveTable.getOID(curveName).let { oid -> ECNamedDomainParameters(oid, ECNamedCurveTable.getByOID(oid)) }

      else -> error("unreachable")
    }
  }

  private val suiteId: ByteArray by lazy { "KEM".encodeToByteArray() + uint16(id.toUShort()).encode() }

  fun generatePrivateKey(): AsymmetricCipherKeyPair = deriveKeyPair(ByteArray(nsk.toInt()).also(RANDOM::nextBytes))

  fun deriveKeyPair(ikm: ByteArray): AsymmetricCipherKeyPair =
    Hkdf(hash).let { hkdf ->
      when (this) {
        P256_SHA256, P384_SHA384, P521_SHA512 -> {
          val dkpPrk = hkdf.labeledExtract(null, suiteId, "dkp_prk", ikm)
          val counterArray = ByteArray(1)

          generateSequence(0) { it + 1 }
            .take(256)
            .map { counter ->
              counterArray[0] = counter.toByte()
              val bytes = hkdf.labeledExpand(dkpPrk, suiteId, "candidate", counterArray, nsk)
              bytes[0] = (bytes[0].toInt() and bitmask.toInt()).toByte()

              // generating keypair
              BigInteger(1, bytes)
            }
            .filter(::validateSk)
            .map { d ->
              val q = FixedPointCombMultiplier().multiply(domainParams.g, d)
              val sk = ECPrivateKeyParameters(d, domainParams)
              val pk = ECPublicKeyParameters(q, domainParams)
              AsymmetricCipherKeyPair(pk, sk)
            }
            .firstOrNull()
            ?: error("DeriveKeyPairError")
        }

        X25519_SHA256 -> {
          val dkpPrk = hkdf.labeledExtract(null, suiteId, "dkp_prk", ikm)
          val skBytes = hkdf.labeledExpand(dkpPrk, suiteId, "sk", null, nsk)
          val sk = X25519PrivateKeyParameters(skBytes)

          return AsymmetricCipherKeyPair(sk.generatePublicKey(), sk)
        }

        X448_SHA512 -> {
          val dkpPrk = hkdf.labeledExtract(null, suiteId, "dkp_prk", ikm)
          val x448sk = hkdf.labeledExpand(dkpPrk, suiteId, "sk", null, nsk)
          val x448params = X448PrivateKeyParameters(x448sk)

          AsymmetricCipherKeyPair(x448params.generatePublicKey(), x448params)
        }
      }
    }

  fun reconstructPublicKey(privateKey: HpkePrivateKey): HpkeKeyPair =
    HpkeKeyPair(
      privateKey,
      when (this) {
        P256_SHA256, P384_SHA384, P521_SHA512 ->
          HpkePublicKey(
            FixedPointCombMultiplier()
              .multiply(domainParams.g, BigInteger(1, privateKey.bytes))
              .getEncoded(false),
          )

        X25519_SHA256 ->
          HpkePublicKey(
            X25519PrivateKeyParameters(privateKey.bytes)
              .generatePublicKey()
              .encoded,
          )

        X448_SHA512 ->
          HpkePublicKey(
            X448PrivateKeyParameters(privateKey.bytes)
              .generatePublicKey()
              .encoded,
          )
      },
    )

  private fun validateSk(d: BigInteger): Boolean {
    val n = domainParams.n
    val nBitLength = n.bitLength()
    val minWeight = nBitLength ushr 2

    if (d < BigInteger.ONE || d >= n) {
      return false
    }

    if (WNafUtil.getNafWeight(d) < minWeight) {
      return false
    }

    return true
  }

  companion object {
    private val RANDOM = SecureRandom()
  }
}
