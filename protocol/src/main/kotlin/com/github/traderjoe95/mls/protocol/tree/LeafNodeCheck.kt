package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.types.ExtensionType
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import java.time.Instant

context(AuthenticationService<Identity>, ICipherSuite, Raise<LeafNodeCheckError>)
suspend fun <Identity : Any> LeafNode<*>.validate(
  underTree: RatchetTreeOps,
  groupContext: GroupContext,
  leafIdx: LeafIndex,
  expectedSource: LeafNodeSource? = null,
) = with(underTree) {
  // Authenticate Credential with AS
  authenticateCredential(this@validate)

  // Verify leaf node signature
  verifySignature(groupContext.groupId, leafIdx)

  // Check that leaf node is compatible with group requirements
  groupContext.extension<RequiredCapabilities>()?.let { requiredCapabilities ->
    if (!requiredCapabilities.isCompatible(capabilities)) {
      raise(LeafNodeCheckError.UnsupportedCapabilities(leafIdx, requiredCapabilities, capabilities))
    }
  }

  checkCredentialSupport()

  // Check lifetime
  lifetime?.let { lt ->
    Instant.now().let { now ->
      if (lt.notBeforeInstant > now || lt.notAfterInstant < now) {
        raise(LeafNodeCheckError.LifetimeExceeded(lt.notBeforeInstant, lt.notAfterInstant, now))
      }
    }
  }

  // Check that the leaf node supports all its extensions
  extensions.map { it.type }
    .filterNot { capabilities supportsExtension it }
    .takeIf { it.isNotEmpty() }
    ?.let { unsupported ->
      raise(LeafNodeCheckError.UnsupportedExtensions(leafIdx, unsupported.map { ExtensionType(it) ?: it }.toSet()))
    }

  when (expectedSource) {
    is LeafNodeSource.KeyPackage,
    is LeafNodeSource.Commit,
    ->
      if (source != expectedSource) raise(LeafNodeCheckError.WrongSource(expectedSource, source))
    is LeafNodeSource.Update ->
      if (source != LeafNodeSource.Update) {
        raise(LeafNodeCheckError.WrongSource(LeafNodeSource.Update, source))
      } else if (encryptionKey.eq(underTree.leafNode(leafIdx).encryptionKey)) {
        raise(LeafNodeCheckError.UpdateShouldChangeEncryptionKey(leafIdx))
      }
    else -> {}
  }

  checkDuplicateKeys(leafIdx)
}

context(RatchetTreeOps, ICipherSuite, Raise<LeafNodeCheckError>)
private fun LeafNode<*>.checkCredentialSupport() {
  // Check that the credentials of all members are supported by the leaf node
  nonBlankLeafIndices.filter {
    leafNode(it).credential.credentialType !in capabilities
  }.let {
    if (it.isNotEmpty()) raise(LeafNodeCheckError.UnsupportedMemberCredential(it))
  }

  // Check that all members support the credential of this leaf node
  nonBlankLeafIndices.filter {
    credential.credentialType !in leafNode(it).capabilities
  }.let {
    if (it.isNotEmpty()) raise(LeafNodeCheckError.MemberDoesNotSupportCredential(it))
  }
}

context(RatchetTreeOps, ICipherSuite, Raise<LeafNodeCheckError>)
private fun LeafNode<*>.checkDuplicateKeys(leafIdx: LeafIndex) {
  // Check for duplicated encryption keys
  nonBlankLeafIndices.filter {
    it != leafIdx && leafNode(it).encryptionKey.eq(encryptionKey)
  }.let { duplicates ->
    if (duplicates.isNotEmpty()) {
      raise(
        LeafNodeCheckError.DuplicateEncryptionKey(duplicates.map { it.nodeIndex } + leafIdx.nodeIndex),
      )
    }
  }

  // Check for duplicated signature keys
  nonBlankLeafIndices.filter {
    it != leafIdx && leafNode(it).verificationKey.eq(verificationKey)
  }.let { duplicates ->
    if (duplicates.isNotEmpty()) raise(LeafNodeCheckError.DuplicateSignatureKey(duplicates + leafIdx))
  }
}
