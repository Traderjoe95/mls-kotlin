package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType

sealed interface ProposalValidationError : CommitError {
  data class BadExternalProposal(val proposalType: ProposalType, val senderType: SenderType) : ProposalValidationError
}

sealed interface KeyPackageValidationError : AddValidationError {
  data class IncompatibleCipherSuite(val keyPackage: CipherSuite, val group: CipherSuite) : KeyPackageValidationError

  data class IncompatibleProtocolVersion(val keyPackage: ProtocolVersion, val group: ProtocolVersion) :
    KeyPackageValidationError

  data class InitKeyReuseAsEncryptionKey(val keyPackage: KeyPackage) : KeyPackageValidationError
}

sealed interface AddValidationError : ProposalValidationError, CreateAddError

sealed interface UpdateValidationError : ProposalValidationError, CreateUpdateError

sealed interface RemoveValidationError : ProposalValidationError, CreateRemoveError {
  data class BlankLeafRemoved(val leafIndex: LeafIndex) : RemoveValidationError

  data class UnauthorizedExternalRemove(val leafIndex: LeafIndex) : RemoveValidationError
}

sealed interface PreSharedKeyValidationError : ProposalValidationError, CreatePreSharedKeyError

sealed interface ReInitValidationError : ProposalValidationError, CreateReInitError {
  data class ReInitDowngrade(val from: ProtocolVersion, val to: ProtocolVersion) : ReInitValidationError
}

sealed interface GroupContextExtensionsValidationError : ProposalValidationError, CreateGroupContextExtensionsError
