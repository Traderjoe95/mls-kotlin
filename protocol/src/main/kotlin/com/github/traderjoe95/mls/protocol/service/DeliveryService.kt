package com.github.traderjoe95.mls.protocol.service

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.GetGroupInfoError
import com.github.traderjoe95.mls.protocol.error.KeyPackageRetrievalError
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

interface DeliveryService<Identity : Any> {
  suspend fun getPublicGroupInfo(groupId: GroupId): Either<GetGroupInfoError, GroupInfo>

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
