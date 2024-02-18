package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference.Companion.asHashReference
import com.github.traderjoe95.mls.protocol.types.crypto.RefHashInput
import com.github.traderjoe95.mls.protocol.types.crypto.RefHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ProposalOrRef.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage.Companion.encodeUnsafe

interface Hash {
  fun makeKeyPackageRef(keyPackage: KeyPackage): KeyPackage.Ref

  fun makeProposalRef(proposal: Proposal): Proposal.Ref

  fun refHash(
    label: String,
    input: ByteArray,
  ): HashReference

  fun hash(input: ByteArray): ByteArray

  abstract class Provider : Hash {
    final override fun makeKeyPackageRef(keyPackage: KeyPackage): KeyPackage.Ref =
      refHash(
        RefHashInput.keyPackage(keyPackage.encodeUnsafe()),
      ).asRef

    final override fun makeProposalRef(proposal: Proposal): Proposal.Ref =
      refHash(
        RefHashInput.proposal(proposal.encodeUnsafe()),
      ).asProposalRef

    final override fun refHash(
      label: String,
      input: ByteArray,
    ): HashReference = refHash(RefHashInput(label, input))

    private fun refHash(input: RefHashInput): HashReference = hash(input.encodeUnsafe()).asHashReference
  }
}
