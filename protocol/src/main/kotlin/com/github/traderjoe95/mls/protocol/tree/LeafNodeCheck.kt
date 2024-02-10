package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.DuplicateEncryptionKey
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.types.ExtensionType
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import java.time.Instant

context(ApplicationCtx<Identity>, RatchetTree, ICipherSuite, Raise<LeafNodeCheckError>)
suspend fun <Identity : Any> LeafNode<*>.validate(
  groupContext: GroupContext,
  leafIdx: UInt,
  expectedSource: LeafNodeSource? = null,
) {
  // Authenticate Credential with AS
  authenticateCredential(this)

  // Verify leaf node signature
  verifySignature(groupContext.groupId, leafIdx)

  // Check that leaf node is compatible with group requirements
  groupContext.extension<RequiredCapabilities>()?.let { requiredCapabilities ->
    if (!requiredCapabilities.isCompatible(capabilities)) {
      raise(LeafNodeCheckError.UnsupportedCapabilities(leafIdx, requiredCapabilities, capabilities))
    }
  }

  // Check that the leaf node supports all its extensions
  extensions.map { it.type }
    .filterNot { capabilities supportsExtension it }
    .takeIf { it.isNotEmpty() }
    ?.let { unsupported ->
      raise(LeafNodeCheckError.UnsupportedExtensions(leafIdx, unsupported.map { ExtensionType(it) ?: it }.toSet()))
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

  // Check for the expected leaf node source, if any
  expectedSource?.takeIf { it != source }?.let { raise(LeafNodeCheckError.WrongSource(expectedSource, source)) }

  checkDuplicateKeys(leafIdx)
}

context(RatchetTree, ICipherSuite, Raise<LeafNodeCheckError>)
private fun LeafNode<*>.checkCredentialSupport() {
  // Check that the credentials of all members are supported by the leaf node
  nonBlankLeafNodes.filter {
    leafNode(it).credential.credentialType !in capabilities
  }.let {
    if (it.isNotEmpty()) raise(LeafNodeCheckError.UnsupportedMemberCredential(it.map { l -> l / 2U }))
  }

  // Check that all members support the credential of this leaf node
  nonBlankLeafNodes.filter {
    credential.credentialType !in leafNode(it).capabilities
  }.let {
    if (it.isNotEmpty()) raise(LeafNodeCheckError.MemberDoesNotSupportCredential(it.map { l -> l / 2U }))
  }
}

context(RatchetTree, ICipherSuite, Raise<LeafNodeCheckError>)
private fun LeafNode<*>.checkDuplicateKeys(leafIdx: UInt) {
  // Check for duplicated encryption keys
  nonBlankLeafNodes.filter {
    it > leafIdx.leafNodeIndex && leafNode(it).encryptionKey.eq(encryptionKey)
  }.let {
    if (it.isNotEmpty()) raise(DuplicateEncryptionKey(it + (leafIdx * 2U)))
  }

  // Check for duplicated signature keys
  nonBlankLeafNodes.filter {
    it > leafIdx.leafNodeIndex && leafNode(it).verificationKey.eq(verificationKey)
  }.let {
    if (it.isNotEmpty()) raise(LeafNodeCheckError.DuplicateSignatureKey(it + (leafIdx * 2U)))
  }
}
