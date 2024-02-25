package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

sealed interface KeyPackageRetrievalError<out Identity : Any> : ResumptionError {
  data class NoKeyPackage(val protocolVersion: ProtocolVersion, val cipherSuite: CipherSuite) :
    KeyPackageRetrievalError<Nothing>
}

sealed interface SendToGroupError

sealed interface SendToUserError<out Identity : Any>

sealed interface SendError : SendToUserError<Nothing>, SendToGroupError

sealed interface GetGroupInfoError {
  data class GroupNotPublic(val groupId: GroupId) : GetGroupInfoError
}

data class UnknownUser<Identity : Any>(
  val identity: Identity,
) : SendToUserError<Identity>, KeyPackageRetrievalError<Identity>

sealed interface DeliveryServiceError :
  KeyPackageRetrievalError<Nothing>,
  SendToGroupError,
  SendToUserError<Nothing>,
  GetGroupInfoError
