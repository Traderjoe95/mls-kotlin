package com.github.traderjoe95.mls.protocol.service

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.GetGroupInfoError
import com.github.traderjoe95.mls.protocol.error.KeyPackageRetrievalError
import com.github.traderjoe95.mls.protocol.error.SendToGroupError
import com.github.traderjoe95.mls.protocol.error.SendToUserError
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import de.traderjoe.ulid.ULID

interface DeliveryService<Identity : Any> {
  suspend fun sendMessageToGroup(
    message: MlsMessage<*>,
    toGroup: ULID,
  ): Either<SendToGroupError, ULID>

  suspend fun sendMessageToIdentity(
    message: MlsMessage<*>,
    to: Identity,
  ): Either<SendToUserError<Identity>, ULID>

  suspend fun sendMessageToIdentities(
    message: MlsMessage<*>,
    vararg to: Identity,
  ): Map<Identity, Either<SendToUserError<Identity>, ULID>> = sendMessageToIdentities(message, to.asList())

  suspend fun sendMessageToIdentities(
    message: MlsMessage<*>,
    to: List<Identity>,
  ): Map<Identity, Either<SendToUserError<Identity>, ULID>>

  suspend fun getPublicGroupInfo(groupId: ULID): Either<GetGroupInfoError, GroupInfo>

  suspend fun getKeyPackage(
    protocolVersion: ProtocolVersion,
    cipherSuite: CipherSuite,
    forUser: Identity,
  ): Either<KeyPackageRetrievalError<Identity>, KeyPackage>

  suspend fun getKeyPackages(
    protocolVersion: ProtocolVersion,
    cipherSuite: CipherSuite,
    vararg forUsers: Identity,
  ): Map<Identity, Either<KeyPackageRetrievalError<Identity>, KeyPackage>> = getKeyPackages(protocolVersion, cipherSuite, forUsers.asList())

  suspend fun getKeyPackages(
    protocolVersion: ProtocolVersion,
    cipherSuite: CipherSuite,
    forUsers: List<Identity>,
  ): Map<Identity, Either<KeyPackageRetrievalError<Identity>, KeyPackage>>
}
