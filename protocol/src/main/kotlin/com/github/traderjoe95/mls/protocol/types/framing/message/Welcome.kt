package com.github.traderjoe95.mls.protocol.types.framing.message

import arrow.core.Option
import arrow.core.some
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

data class Welcome(
  val cipherSuite: CipherSuite,
  val secrets: List<EncryptedGroupSecrets>,
  val encryptedGroupInfo: Ciphertext,
) : Message, Struct3T.Shape<CipherSuite, List<EncryptedGroupSecrets>, Ciphertext> {
  companion object {
    val T: DataType<Welcome> =
      struct("Welcome") {
        it.field("cipher_suite", CipherSuite.T)
          .field("secrets", EncryptedGroupSecrets.T[V])
          .field("encrypted_group_info", Ciphertext.T)
      }.lift(::Welcome)
  }
}

data class PathSecret(val pathSecret: Secret) : Struct1T.Shape<Secret> {
  companion object {
    val T: DataType<PathSecret> =
      struct("PathSecret") {
        it.field("path_secret", Secret.T)
      }.lift(::PathSecret)
  }
}

data class GroupSecrets(
  val joinerSecret: Secret,
  val pathSecret: Option<PathSecret>,
  val preSharedKeyIds: List<PreSharedKeyId>,
) : Struct3T.Shape<Secret, Option<PathSecret>, List<PreSharedKeyId>> {
  constructor(joinerSecret: Secret, pathSecret: Secret, preSharedKeyIds: List<PreSharedKeyId>) : this(
    joinerSecret,
    PathSecret(pathSecret).some(),
    preSharedKeyIds,
  )

  companion object {
    val T: DataType<GroupSecrets> =
      struct("GroupSecrets") {
        it.field("joiner_secret", Secret.T)
          .field("path_secret", optional[PathSecret.T])
          .field("psks", PreSharedKeyId.T[V])
      }.lift(::GroupSecrets)
  }
}

data class EncryptedGroupSecrets(
  val newMember: KeyPackage.Ref,
  val encryptedGroupSecrets: HpkeCiphertext,
) : Struct2T.Shape<KeyPackage.Ref, HpkeCiphertext> {
  companion object {
    val T: DataType<EncryptedGroupSecrets> =
      struct("GroupSecrets") {
        it.field("new_member", KeyPackage.Ref.T)
          .field("encrypted_group_secrets", HpkeCiphertext.T)
      }.lift(::EncryptedGroupSecrets)
  }
}
