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
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce.Companion.asNonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.modes.AEADCipher
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
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

  override fun deriveKeyPair(secret: Secret): HpkeKeyPair = dhKem.deriveKeyPair(secret.bytes).asHpkeKeyPair

  override fun reconstructPublicKey(privateKey: HpkePrivateKey): HpkeKeyPair = dhKem.reconstructPublicKey(privateKey)

  override fun encryptAead(
    key: Secret,
    nonce: Nonce,
    aad: Aad,
    plaintext: ByteArray,
  ): Ciphertext =
    with(aead()) {
      init(true, ParametersWithIV(KeyParameter(key.bytes), nonce.bytes))
      processAADBytes(aad.bytes, 0, aad.bytes.size)

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
      init(false, ParametersWithIV(KeyParameter(key.bytes), nonce.bytes))
      processAADBytes(aad.bytes, 0, aad.bytes.size)

      catch(
        block = {
          ByteArray(getOutputSize(ciphertext.size)).also { out ->
            val written = processBytes(ciphertext.bytes, 0, ciphertext.size, out, 0)
            doFinal(out, written)
          }
        },
        catch = { raise(DecryptError.AeadDecryptionFailed) },
      )
    }

  override fun decryptWithLabel(
    privateKey: HpkePrivateKey,
    label: String,
    context: ByteArray,
    ciphertext: HpkeCiphertext,
  ): ByteArray = decryptWithLabel(dhKem.reconstructPublicKey(privateKey), label, context, ciphertext)

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
      kemOutput.bytes,
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
      aad.bytes,
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
      kemOutput.bytes,
      keyPair.asParameter,
      context.encodeUnsafe(),
      aad.bytes,
      ciphertext.bytes,
      null,
      null,
      null,
    )

  override fun generateSecret(len: UShort): Secret = ByteArray(len.toInt()).also(rand::nextBytes).asSecret

  override fun generateNonce(len: UShort): Nonce = ByteArray(len.toInt()).also(rand::nextBytes).asNonce

  override fun generateHpkeKeyPair(): HpkeKeyPair = dhKem.generatePrivateKey().asHpkeKeyPair

  private fun aead(): AEADCipher = aeadAlgorithm.createCipher()

  private val AsymmetricCipherKeyPair.asHpkeKeyPair: HpkeKeyPair
    get() =
      HpkeKeyPair(
        HpkePrivateKey(hpke.serializePrivateKey(private)),
        HpkePublicKey(hpke.serializePublicKey(public)),
      )

  private val HpkePublicKey.asParameter: AsymmetricKeyParameter
    get() = hpke.deserializePublicKey(bytes)

  private val HpkeKeyPair.asParameter: AsymmetricCipherKeyPair
    get() = hpke.deserializePrivateKey(private.bytes, public.bytes)
}
