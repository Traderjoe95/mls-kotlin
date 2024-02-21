package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

sealed interface KeyPackageMismatchError : GroupCreationError, JoinError {
  data class ProtocolVersionMismatch(val group: ProtocolVersion, val keyPackage: ProtocolVersion) : KeyPackageMismatchError

  data class CipherSuiteMismatch(val group: CipherSuite, val keyPackage: CipherSuite) : KeyPackageMismatchError
}
