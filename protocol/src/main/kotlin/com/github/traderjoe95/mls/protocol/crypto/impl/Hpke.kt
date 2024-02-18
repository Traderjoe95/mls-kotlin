package com.github.traderjoe95.mls.protocol.crypto.impl

import arrow.core.raise.Raise
import arrow.core.raise.catch
import com.github.traderjoe95.mls.protocol.crypto.Encrypt
import com.github.traderjoe95.mls.protocol.crypto.Gen
import com.github.traderjoe95.mls.protocol.crypto.Kem
import com.github.traderjoe95.mls.protocol.error.DecryptError
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext.Companion.asCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.EncryptContext
import com.github.traderjoe95.mls.protocol.types.crypto.EncryptContext.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput.Companion.asKemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.modes.AEADCipher
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import java.security.SecureRandom

internal class Hpke(
  private val dhKem: DhKem,
  private val aeadAlgorithm: AeadAlgorithm,
  private val rand: SecureRandom = SecureRandom(),
) : Encrypt.Provider(), Kem, Gen {
  private val hpke: HPKE = HPKE(HPKE.mode_base, dhKem.id, dhKem.hash.hkdfId, aeadAlgorithm.id)

  override val keyLen: UShort
    get() = aeadAlgorithm.keyLen
  override val nonceLen: UShort
    get() = aeadAlgorithm.nonceLen

  private val exporterContext: ByteArray by lazy {
    "MLS 1.0 external init secret".encodeToByteArray()
  }

  override fun deriveKeyPair(secret: Secret): HpkeKeyPair = hpke.deriveKeyPair(secret.key).asHpkeKeyPair

  override fun encryptAead(
    key: Secret,
    nonce: Nonce,
    aad: Aad,
    plaintext: ByteArray,
  ): Ciphertext =
    with(aead()) {
      init(true, ParametersWithIV(KeyParameter(key.key), nonce.value))
      processAADBytes(aad.data, 0, aad.data.size)

      ByteArray(getOutputSize(plaintext.size)).also { out ->
        val written = processBytes(plaintext, 0, plaintext.size, out, 0)
        doFinal(out, written)
      }.asCiphertext
    }

  context(Raise<DecryptError>)
  override fun decryptAead(
    key: Secret,
    nonce: Nonce,
    aad: Aad,
    ciphertext: Ciphertext,
  ): ByteArray =
    with(aead()) {
      init(false, ParametersWithIV(KeyParameter(key.key), nonce.value))
      processAADBytes(aad.data, 0, aad.data.size)

      catch(
        block = {
          ByteArray(getOutputSize(ciphertext.size)).also { out ->
            val written = processBytes(ciphertext.value, 0, ciphertext.size, out, 0)
            doFinal(out, written)
          }
        },
        catch = { raise(DecryptError.AeadDecryptionFailed) },
      )
    }

  override fun export(
    publicKey: HpkePublicKey,
    info: String,
  ): Pair<KemOutput, Secret> =
    hpke.sendExport(
      publicKey.asParameter,
      info.encodeToByteArray(),
      exporterContext,
      dhKem.hash.hashLen.toInt(),
      null,
      null,
      null,
    ).let { (kemOutput, secret) ->
      kemOutput.asKemOutput to secret.asSecret
    }

  override fun export(
    kemOutput: KemOutput,
    keyPair: HpkeKeyPair,
    info: String,
  ): Secret =
    hpke.receiveExport(
      kemOutput.value,
      keyPair.asParameter,
      info.encodeToByteArray(),
      exporterContext,
      dhKem.hash.hashLen.toInt(),
      null,
      null,
      null,
    ).asSecret

  override fun sealBase(
    publicKey: HpkePublicKey,
    context: EncryptContext,
    aad: Aad,
    plaintext: ByteArray,
  ): HpkeCiphertext =
    hpke.seal(
      publicKey.asParameter,
      context.encodeUnsafe(),
      aad.data,
      plaintext,
      null,
      null,
      null,
    ).let { (ct, kemOutput) ->
      HpkeCiphertext(kemOutput.asKemOutput, ct.asCiphertext)
    }

  override fun openBase(
    kemOutput: KemOutput,
    keyPair: HpkeKeyPair,
    context: EncryptContext,
    aad: Aad,
    ciphertext: Ciphertext,
  ): ByteArray =
    hpke.open(
      kemOutput.value,
      keyPair.asParameter,
      context.encodeUnsafe(),
      aad.data,
      ciphertext.value,
      null,
      null,
      null,
    )

  override fun generateSecret(len: UShort): Secret = ByteArray(len.toInt()).also { rand.nextBytes(it) }.asSecret

  override fun generateHpkeKeyPair(): HpkeKeyPair = kpg().generateKeyPair().asHpkeKeyPair

  private fun aead(): AEADCipher = aeadAlgorithm.createCipher()

  private fun kpg(): AsymmetricCipherKeyPairGenerator =
    when (dhKem) {
      DhKem.P256_SHA256 -> ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(secp256r1, rand)) }
      DhKem.P384_SHA384 -> ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(secp384r1, rand)) }
      DhKem.P521_SHA512 -> ECKeyPairGenerator().apply { init(ECKeyGenerationParameters(secp521r1, rand)) }

      DhKem.X25519_SHA256 -> X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(rand)) }
      DhKem.X448_SHA512 -> X448KeyPairGenerator().apply { init(X448KeyGenerationParameters(rand)) }
    }

  private val AsymmetricCipherKeyPair.asHpkeKeyPair: HpkeKeyPair
    get() =
      HpkeKeyPair(
        HpkePrivateKey(hpke.serializePrivateKey(private)) to HpkePublicKey(hpke.serializePublicKey(public)),
      )

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

  private val HpkePublicKey.asParameter: AsymmetricKeyParameter
    get() = hpke.deserializePublicKey(key)

  private val HpkeKeyPair.asParameter: AsymmetricCipherKeyPair
    get() = hpke.deserializePrivateKey(private.key, public.key)
}
