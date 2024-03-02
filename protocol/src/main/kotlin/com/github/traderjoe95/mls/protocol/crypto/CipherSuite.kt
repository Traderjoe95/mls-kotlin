package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.Either
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.crypto.impl.AeadAlgorithm
import com.github.traderjoe95.mls.protocol.crypto.impl.CipherSuiteImpl.Companion.using
import com.github.traderjoe95.mls.protocol.crypto.impl.DhKem
import com.github.traderjoe95.mls.protocol.error.CreateSignatureError
import com.github.traderjoe95.mls.protocol.error.DecryptError
import com.github.traderjoe95.mls.protocol.error.HpkeDecryptError
import com.github.traderjoe95.mls.protocol.error.HpkeEncryptError
import com.github.traderjoe95.mls.protocol.error.ReceiveExportError
import com.github.traderjoe95.mls.protocol.error.ReconstructHpkePublicKeyError
import com.github.traderjoe95.mls.protocol.error.ReconstructSignaturePublicKeyError
import com.github.traderjoe95.mls.protocol.error.SendExportError
import com.github.traderjoe95.mls.protocol.error.VerifySignatureError
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import kotlin.random.Random

interface ICipherSuite : Sign, Encrypt, Hash, Auth, Kdf, Kem, Gen

enum class CipherSuite(
  ord: UInt,
  cipherSuite: ICipherSuite,
  override val isValid: Boolean = true,
) : ProtocolEnum<CipherSuite>, ICipherSuite by cipherSuite {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0U, Dummy, false),

  X25519_AES128_SHA256_ED25519(1U, using(DhKem.X25519_SHA256, AeadAlgorithm.AesGcm128)),
  P256_AES128_SHA256_P256(2U, using(DhKem.P256_SHA256, AeadAlgorithm.AesGcm128)),
  X25519_CHACHA20_SHA256_ED25519(3U, using(DhKem.X25519_SHA256, AeadAlgorithm.ChaCha20Poly1305)),
  X448_AES256_SHA512_ED448(4U, using(DhKem.X448_SHA512, AeadAlgorithm.AesGcm256)),
  P521_AES256_SHA512_P521(5U, using(DhKem.P521_SHA512, AeadAlgorithm.AesGcm256)),
  X448_CHACHA20_SHA512_ED448(6U, using(DhKem.X448_SHA512, AeadAlgorithm.ChaCha20Poly1305)),
  P384_AES256_SHA512_P384(7U, using(DhKem.P384_SHA384, AeadAlgorithm.AesGcm256)),

  // GREASE
  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_1(0x0A0AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_2(0x1A1AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_3(0x2A2AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_4(0x3A3AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_5(0x4A4AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_6(0x5A5AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_7(0x6A6AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_8(0x7A7AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_9(0x8A8AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_10(0x9A9AU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_11(0xAAAAU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_12(0xBABAU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_13(0xCACAU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_14(0xDADAU, Dummy, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_15(0xEAEAU, Dummy, false),
  ;

  override val ord: UIntRange = ord..ord
  val asUShort: UShort = ord.toUShort()

  override fun toString(): String = "$name[$asUShort]"

  companion object {
    val T: EnumT<CipherSuite> = throwAnyError { enum(upperBound = 0xFFFFU) }

    val validEntries: List<CipherSuite> = entries.filter(CipherSuite::isValid)
    val VALID: List<UShort> = validEntries.map { it.asUShort }

    operator fun invoke(type: UShort): CipherSuite? = entries.find { it.isValid && type in it.ord }

    val ICipherSuite.zeroesNh: Secret
      get() = Secret.zeroes(hashLen.toUInt())

    fun grease(individualProbability: Double = 0.1): List<UShort> =
      entries
        .filter { it.name.startsWith("GREASE") && Random.nextDouble() < individualProbability }
        .map { it.asUShort }
  }
}

internal object Dummy : ICipherSuite {
  override fun signWithLabel(
    signatureKey: SignaturePrivateKey,
    label: String,
    content: ByteArray,
  ): Either<CreateSignatureError, Signature> = error("unsupported")

  override fun verifyWithLabel(
    signaturePublicKey: SignaturePublicKey,
    label: String,
    content: ByteArray,
    signature: Signature,
  ): Either<VerifySignatureError, Unit> = error("unsupported")

  override fun generateSignatureKeyPair(): SignatureKeyPair = error("unsupported")

  override fun reconstructPublicKey(privateKey: SignaturePrivateKey): Either<ReconstructSignaturePublicKeyError, SignatureKeyPair> =
    error("unsupported")

  override fun encryptWithLabel(
    publicKey: HpkePublicKey,
    label: String,
    context: ByteArray,
    plaintext: ByteArray,
  ): Either<HpkeEncryptError, HpkeCiphertext> = error("unsupported")

  override fun decryptWithLabel(
    keyPair: HpkeKeyPair,
    label: String,
    context: ByteArray,
    ciphertext: HpkeCiphertext,
  ): Either<HpkeDecryptError, ByteArray> = error("unsupported")

  override fun decryptWithLabel(
    privateKey: HpkePrivateKey,
    label: String,
    context: ByteArray,
    ciphertext: HpkeCiphertext,
  ): Either<HpkeDecryptError, ByteArray> = error("unsupported")

  override fun encryptAead(
    key: Secret,
    nonce: Nonce,
    aad: Aad,
    plaintext: ByteArray,
  ): Ciphertext = error("unsupported")

  override fun decryptAead(
    key: Secret,
    nonce: Nonce,
    aad: Aad,
    ciphertext: Ciphertext,
  ): Either<DecryptError, ByteArray> = error("unsupported")

  override fun export(
    publicKey: HpkePublicKey,
    info: String,
  ): Either<SendExportError, Pair<KemOutput, Secret>> = error("unsupported")

  override fun export(
    kemOutput: KemOutput,
    keyPair: HpkeKeyPair,
    info: String,
  ): Either<ReceiveExportError, Secret> = error("unsupported")

  override val keyLen: UShort
    get() = error("unsupported")
  override val nonceLen: UShort
    get() = error("unsupported")

  override fun makeKeyPackageRef(keyPackage: KeyPackage): KeyPackage.Ref = error("unsupported")

  override fun makeProposalRef(proposal: AuthenticatedContent<Proposal>): Proposal.Ref = error("unsupported")

  override fun refHash(
    label: String,
    input: ByteArray,
  ): HashReference = error("unsupported")

  override fun hash(input: ByteArray): ByteArray = error("unsupported")

  override fun mac(
    secret: Secret,
    content: ByteArray,
  ): Mac = error("unsupported")

  override fun expandWithLabel(
    secret: Secret,
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret = error("unsupported")

  override fun expandWithLabel(
    secret: Secret,
    label: String,
    context: String,
    length: UShort,
  ): Secret = error("unsupported")

  override fun deriveSecret(
    secret: Secret,
    label: String,
  ): Secret = error("unsupported")

  override fun extract(
    salt: ByteArray,
    ikm: Secret,
  ): Secret = error("unsupported")

  override val hashLen: UShort
    get() = error("unsupported")

  override fun deriveKeyPair(secret: Secret): HpkeKeyPair = error("unsupported")

  override fun reconstructPublicKey(privateKey: HpkePrivateKey): Either<ReconstructHpkePublicKeyError, HpkeKeyPair> = error("unsupported")

  override fun generateSecret(len: UShort): Secret = error("unsupported")

  override fun generateNonce(len: UShort): Nonce = error("unsupported")

  override fun generateHpkeKeyPair(): HpkeKeyPair = error("unsupported")
}
