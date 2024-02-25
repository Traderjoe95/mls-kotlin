package com.github.traderjoe95.mls.protocol.message

import arrow.core.None
import arrow.core.Option
import arrow.core.raise.Raise
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
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

data class Welcome(
  val cipherSuite: CipherSuite,
  val secrets: List<EncryptedGroupSecrets>,
  val encryptedGroupInfo: Ciphertext,
) : Message, Struct3T.Shape<CipherSuite, List<EncryptedGroupSecrets>, Ciphertext> {
  context(Raise<WelcomeJoinError>)
  fun decryptGroupSecrets(keyPackage: KeyPackage.Private): GroupSecrets =
    DecoderError.wrap {
      cipherSuite.decryptWithLabel(
        keyPackage.initKeyPair,
        "Welcome",
        encryptedGroupInfo.bytes,
        secrets
          .find { it.newMember.eq(keyPackage.ref) }
          ?.encryptedGroupSecrets
          ?: raise(WelcomeJoinError.WelcomeNotForYou),
      ).decodeAs(GroupSecrets.dataT)
    }

  context(Raise<WelcomeJoinError>)
  fun decryptGroupSecrets(
    keyPackageRef: KeyPackage.Ref,
    initKeyPair: HpkeKeyPair,
  ): GroupSecrets =
    DecoderError.wrap {
      cipherSuite.decryptWithLabel(
        initKeyPair,
        "Welcome",
        encryptedGroupInfo.bytes,
        secrets
          .find { it.newMember.eq(keyPackageRef) }
          ?.encryptedGroupSecrets
          ?: raise(WelcomeJoinError.WelcomeNotForYou),
      ).decodeAs(GroupSecrets.dataT)
    }

  context(Raise<WelcomeJoinError>)
  fun decryptGroupInfo(
    joinerSecret: Secret,
    pskSecret: Secret,
  ): GroupInfo {
    val joinerExtracted = cipherSuite.extract(joinerSecret, pskSecret)
    val welcomeSecret = cipherSuite.deriveSecret(joinerExtracted, "welcome")

    val nonce = cipherSuite.expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), cipherSuite.nonceLen).asNonce
    val key = cipherSuite.expandWithLabel(welcomeSecret, "key", byteArrayOf(), cipherSuite.keyLen)

    return DecoderError.wrap {
      GroupInfo.decode(cipherSuite.decryptAead(key, nonce, Aad.empty, encryptedGroupInfo))
    }
  }

  companion object : Encodable<Welcome> {
    override val dataT: DataType<Welcome> =
      struct("Welcome") {
        it.field("cipher_suite", CipherSuite.T)
          .field("secrets", EncryptedGroupSecrets.dataT[V])
          .field("encrypted_group_info", Ciphertext.dataT)
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
  ): EncryptedGroupSecrets =
    EncryptedGroupSecrets(
      forKeyPackage.ref,
      cipherSuite.encryptWithLabel(
        forKeyPackage.initKey,
        "Welcome",
        encryptedGroupInfo.bytes,
        encodeUnsafe(),
      ),
    )

  companion object : Encodable<GroupSecrets> {
    override val dataT: DataType<GroupSecrets> =
      struct("GroupSecrets") {
        it.field("joiner_secret", Secret.dataT)
          .field("path_secret", optional[Secret.dataT])
          .field("psks", PreSharedKeyId.dataT[V])
      }.lift(::GroupSecrets)
  }
}

data class EncryptedGroupSecrets(
  val newMember: KeyPackage.Ref,
  val encryptedGroupSecrets: HpkeCiphertext,
) : Struct2T.Shape<KeyPackage.Ref, HpkeCiphertext> {
  companion object : Encodable<EncryptedGroupSecrets> {
    override val dataT: DataType<EncryptedGroupSecrets> =
      struct("GroupSecrets") {
        it.field("new_member", KeyPackage.Ref.dataT)
          .field("encrypted_group_secrets", HpkeCiphertext.dataT)
      }.lift(::EncryptedGroupSecrets)
  }
}
