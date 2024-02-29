package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.NodeIndex
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import java.time.Instant

sealed interface TreeCheckError : JoinError {
  data class BadTreeHash(val expected: ByteArray, val actual: ByteArray) : TreeCheckError

  data class NotParentHashValid(val nodeIdx: NodeIndex) : TreeCheckError

  data class BadUnmergedLeaf(val parentIdx: NodeIndex, val unmergedLeafIdx: LeafIndex, val reason: String) :
    TreeCheckError
}

sealed interface LeafNodeCheckError : TreeCheckError, InvalidCommit, KeyPackageValidationError, UpdateValidationError {
  data class UnsupportedCapabilities(
    val leafIdx: LeafIndex,
    val requiredCapabilities: RequiredCapabilities,
    val capabilities: Capabilities,
  ) : LeafNodeCheckError, ExtensionSupportError, GroupContextExtensionsValidationError

  data class UnsupportedMemberCredential(val leafIndices: List<LeafIndex>) : LeafNodeCheckError

  data class MemberDoesNotSupportCredential(val leafIndices: List<LeafIndex>) : LeafNodeCheckError

  data class LifetimeExceeded(val notBefore: Instant, val notAfter: Instant, val now: Instant) : LeafNodeCheckError

  data class UnsupportedExtensions(val leafIdx: LeafIndex, val extensions: Set<Any>) :
    LeafNodeCheckError,
    GroupContextExtensionsValidationError

  data class WrongSource(val expected: LeafNodeSource, val actual: LeafNodeSource) : LeafNodeCheckError

  data class DuplicateSignatureKey(val leafIndices: List<LeafIndex>) : LeafNodeCheckError

  data class DuplicateEncryptionKey(val nodeIndices: List<NodeIndex>) : LeafNodeCheckError

  data class UpdateShouldChangeEncryptionKey(val leafIdx: LeafIndex) : LeafNodeCheckError
}
