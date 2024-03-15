package com.github.traderjoe95.mls.protocol.message

import arrow.core.Either
import arrow.core.None
import arrow.core.Option
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.HpkeDecryptError
import com.github.traderjoe95.mls.protocol.error.HpkeEncryptError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class Welcome(
  val cipherSuite: CipherSuite,
  val secrets: List<EncryptedGroupSecrets>,
  val encryptedGroupInfo: Ciphertext,
) : Message, Struct3T.Shape<CipherSuite, List<EncryptedGroupSecrets>, Ciphertext> {
  override val wireFormat: WireFormat = WireFormat.MlsWelcome

  override val encoded: ByteArray by lazy { encodeUnsafe() }

  fun decryptGroupSecrets(keyPackage: KeyPackage.Private): Either<WelcomeJoinError, GroupSecrets> =
    decryptGroupSecrets(keyPackage.ref, keyPackage.initKeyPair)

  fun decryptGroupSecrets(
    keyPackageRef: KeyPackage.Ref,
    initKeyPair: HpkeKeyPair,
  ): Either<WelcomeJoinError, GroupSecrets> =
    either {
      secrets
        .find { it.newMember.eq(keyPackageRef) }
        ?.decrypt(cipherSuite, initKeyPair, encryptedGroupInfo)
        ?: raise(WelcomeJoinError.NoGroupSecretsForKeyPackage)
    }

  fun decryptGroupInfo(
    joinerSecret: Secret,
    pskSecret: Secret,
  ): Either<WelcomeJoinError, GroupInfo> =
    either {
      val joinerExtracted = cipherSuite.extract(joinerSecret, pskSecret)
      val welcomeSecret = cipherSuite.deriveSecret(joinerExtracted, "welcome")

      val nonce = cipherSuite.expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), cipherSuite.nonceLen).asNonce
      val key = cipherSuite.expandWithLabel(welcomeSecret, "key", byteArrayOf(), cipherSuite.keyLen)

      DecoderError.wrap {
        GroupInfo.decode(cipherSuite.decryptAead(key, nonce, Aad.empty, encryptedGroupInfo).bind())
      }
    }

  companion object : Encodable<Welcome> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<Welcome> =
      struct("Welcome") {
        it.field("cipher_suite", CipherSuite.T)
          .field("secrets", EncryptedGroupSecrets.T[V])
          .field("encrypted_group_info", Ciphertext.T)
      }.lift(::Welcome)
  }
}

data class GroupSecrets(
  val joinerSecret: Secret,
  val pathSecret: Option<Secret> = None,
  val preSharedKeyIds: List<PreSharedKeyId> = listOf(),
) : Struct3T.Shape<Secret, Option<Secret>, List<PreSharedKeyId>> {
  fun encrypt(
    cipherSuite: CipherSuite,
    forKeyPackage: KeyPackage,
    encryptedGroupInfo: Ciphertext,
  ): Either<HpkeEncryptError, EncryptedGroupSecrets> =
    either {
      EncryptedGroupSecrets(
        forKeyPackage.ref,
        cipherSuite.encryptWithLabel(
          forKeyPackage.initKey,
          "Welcome",
          encryptedGroupInfo.bytes,
          encodeUnsafe(),
        ).bind(),
      )
    }

  companion object : Encodable<GroupSecrets> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<GroupSecrets> =
      struct("GroupSecrets") {
        it.field("joiner_secret", Secret.T)
          .field("path_secret", optional[Secret.T])
          .field("psks", PreSharedKeyId.T[V])
      }.lift(::GroupSecrets)
  }
}

data class EncryptedGroupSecrets(
  val newMember: KeyPackage.Ref,
  val encryptedGroupSecrets: HpkeCiphertext,
) : Struct2T.Shape<KeyPackage.Ref, HpkeCiphertext> {
  context(Raise<HpkeDecryptError>, Raise<DecoderError>)
  internal fun decrypt(
    cipherSuite: ICipherSuite,
    initKeyPair: HpkeKeyPair,
    encryptedGroupInfo: Ciphertext,
  ): GroupSecrets =
    DecoderError.wrap {
      cipherSuite.decryptWithLabel(
        initKeyPair,
        "Welcome",
        encryptedGroupInfo.bytes,
        encryptedGroupSecrets,
      ).bind().decodeAs(GroupSecrets.T)
    }

  companion object : Encodable<EncryptedGroupSecrets> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<EncryptedGroupSecrets> =
      struct("GroupSecrets") {
        it.field("new_member", KeyPackage.Ref.T)
          .field("encrypted_group_secrets", HpkeCiphertext.T)
      }.lift(::EncryptedGroupSecrets)
  }
}
