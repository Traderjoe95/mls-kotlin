package com.github.traderjoe95.mls.protocol.group

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.suspending.new

data class GroupSettings(
  val protocolVersion: ProtocolVersion,
  val cipherSuite: CipherSuite,
  val groupId: ULID,
  val keepPastEpochs: UInt = 5U,
  val public: Boolean = false,
) {
  companion object {
    suspend fun new(
      cipherSuite: CipherSuite,
      protocolVersion: ProtocolVersion = ProtocolVersion.MLS_1_0,
      groupId: ULID? = null,
      keepPastEpochs: UInt = 5U,
      public: Boolean = false,
    ): GroupSettings =
      GroupSettings(
        protocolVersion,
        cipherSuite,
        groupId ?: ULID.new(),
        keepPastEpochs,
        public,
      )
  }
}
