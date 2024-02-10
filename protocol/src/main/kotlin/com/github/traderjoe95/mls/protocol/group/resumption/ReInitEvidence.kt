package com.github.traderjoe95.mls.protocol.group.resumption

import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal

data class ReInitEvidence(
  val currentEpoch: ULong,
  val lastCommitProposals: List<Proposal>,
  val members: List<Credential>,
)
