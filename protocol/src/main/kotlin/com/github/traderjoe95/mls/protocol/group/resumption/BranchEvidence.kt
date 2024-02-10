package com.github.traderjoe95.mls.protocol.group.resumption

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

data class BranchEvidence(
  val protocolVersion: ProtocolVersion,
  val cipherSuite: CipherSuite,
  val members: List<Credential>,
)
