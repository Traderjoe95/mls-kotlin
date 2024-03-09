package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.types.ExtensionType
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import java.time.Instant

context(Raise<LeafNodeCheckError>)
fun LeafNode<*>.validate(
  tree: RatchetTreeOps,
  groupContext: GroupContext,
  leafIdx: LeafIndex,
  expectedSource: LeafNodeSource? = null,
) {
  // Verify leaf node signature
  verifySignature(groupContext.cipherSuite, groupContext.groupId, leafIdx).bind()

  // Check that leaf node is compatible with group requirements
  groupContext.extension<RequiredCapabilities>()?.let { requiredCapabilities ->
    if (!requiredCapabilities.isCompatible(capabilities)) {
      raise(LeafNodeCheckError.UnsupportedCapabilities(leafIdx, requiredCapabilities, capabilities))
    }
  }

  checkCredentialSupport(tree)

  // Check lifetime
  lifetime?.let { lt ->
    Instant.now().let { now ->
      if (now in lt) {
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
      } else if (encryptionKey.eq(tree.leafNode(leafIdx).encryptionKey)) {
        raise(LeafNodeCheckError.UpdateShouldChangeEncryptionKey(leafIdx))
      }

    else -> {}
  }

  checkDuplicateKeys(tree, leafIdx)
}

context(Raise<LeafNodeCheckError>)
private fun LeafNode<*>.checkCredentialSupport(tree: RatchetTreeOps) {
  // Check that the credentials of all members are supported by the leaf node
  tree.nonBlankLeafIndices.filter {
    tree.leafNode(it).credential.credentialType !in capabilities
  }.let {
    if (it.isNotEmpty()) raise(LeafNodeCheckError.UnsupportedMemberCredential(it))
  }

  // Check that all members support the credential of this leaf node
  tree.nonBlankLeafIndices.filter {
    credential.credentialType !in tree.leafNode(it).capabilities
  }.let {
    if (it.isNotEmpty()) raise(LeafNodeCheckError.MemberDoesNotSupportCredential(it))
  }
}

context(Raise<LeafNodeCheckError>)
private fun LeafNode<*>.checkDuplicateKeys(
  tree: RatchetTreeOps,
  leafIdx: LeafIndex,
) {
  // Check for duplicated encryption keys
  tree.nonBlankLeafIndices.filter {
    it != leafIdx && tree.leafNode(it).encryptionKey.eq(encryptionKey)
  }.let { duplicates ->
    if (duplicates.isNotEmpty()) {
      raise(
        LeafNodeCheckError.DuplicateEncryptionKey(duplicates.map { it.nodeIndex } + leafIdx.nodeIndex),
      )
    }
  }

  // Check for duplicated signature keys
  tree.nonBlankLeafIndices.filter {
    it != leafIdx && tree.leafNode(it).signaturePublicKey.eq(signaturePublicKey)
  }.let { duplicates ->
    if (duplicates.isNotEmpty()) raise(LeafNodeCheckError.DuplicateSignatureKey(duplicates + leafIdx))
  }
}
