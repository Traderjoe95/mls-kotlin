package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.KeyPackage.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference.Companion.asHashReference
import com.github.traderjoe95.mls.protocol.types.crypto.RefHashInput
import com.github.traderjoe95.mls.protocol.types.crypto.RefHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal

interface Hash {
  fun makeKeyPackageRef(keyPackage: KeyPackage): KeyPackage.Ref

  fun makeProposalRef(proposal: AuthenticatedContent<Proposal>): Proposal.Ref

  fun refHash(
    label: String,
    input: ByteArray,
  ): HashReference

  fun hash(input: ByteArray): ByteArray

  abstract class Provider : Hash {
    final override fun makeKeyPackageRef(keyPackage: KeyPackage): KeyPackage.Ref =
      refHash(
        RefHashInput.keyPackage(keyPackage.encodeUnsafe()),
      ).asKeyPackageRef

    final override fun makeProposalRef(proposal: AuthenticatedContent<Proposal>): Proposal.Ref =
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
