package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import java.time.Instant

sealed interface TreeCheckError : JoinError {
  data class BadTreeHash(val expected: ByteArray, val actual: ByteArray) : TreeCheckError

  data class NotParentHashValid(val nodeIdx: UInt) : TreeCheckError

  data class BadUnmergedLeaf(val parentIdx: UInt, val unmergedLeafIdx: UInt, val reason: String) : TreeCheckError
}

sealed interface LeafNodeCheckError : TreeCheckError, InvalidCommit {
  data class UnsupportedCapabilities(
    val leafIdx: UInt,
    val requiredCapabilities: RequiredCapabilities,
    val capabilities: Capabilities,
  ) : LeafNodeCheckError, ExtensionSupportError

  data class UnsupportedMemberCredential(val leafIndices: List<UInt>) : LeafNodeCheckError

  data class MemberDoesNotSupportCredential(val leafIndices: List<UInt>) : LeafNodeCheckError

  data class LifetimeExceeded(val notBefore: Instant, val notAfter: Instant, val now: Instant) : LeafNodeCheckError

  data class UnsupportedExtensions(val leafIdx: UInt, val extensions: Set<Any>) : LeafNodeCheckError

  data class WrongSource(val expected: LeafNodeSource, val actual: LeafNodeSource) : LeafNodeCheckError

  data class DuplicateSignatureKey(val leafIndices: List<UInt>) : LeafNodeCheckError
}

data class DuplicateEncryptionKey(val nodeIndices: List<UInt>) : LeafNodeCheckError
