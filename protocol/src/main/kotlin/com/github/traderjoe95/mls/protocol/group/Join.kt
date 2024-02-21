package com.github.traderjoe95.mls.protocol.group

import arrow.core.getOrElse
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.crypto.KeyScheduleImpl
import com.github.traderjoe95.mls.protocol.crypto.calculatePskSecret
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.ExtensionSupportError
import com.github.traderjoe95.mls.protocol.error.ExternalJoinError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.resumption.isProtocolResumption
import com.github.traderjoe95.mls.protocol.group.resumption.validateResumption
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.insert
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.join
import com.github.traderjoe95.mls.protocol.tree.check
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.findEquivalentLeaf
import com.github.traderjoe95.mls.protocol.tree.updateOnJoin
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupSecrets
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.framing.message.PublicMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import de.traderjoe.ulid.ULID
import com.github.traderjoe95.mls.protocol.types.RatchetTree as RatchetTreeExt

context(Raise<GroupCreationError>)
suspend fun newGroup(
  keyPackage: KeyPackage.Private,
  vararg extensions: GroupContextExtension<*>,
  protocolVersion: ProtocolVersion = keyPackage.version,
  cipherSuite: CipherSuite = keyPackage.cipherSuite,
  groupId: ULID? = null,
): GroupState {
  keyPackage.checkParametersCompatible(protocolVersion, cipherSuite)

  val ownLeaf = LeafIndex(0U)

  keyPackage.leafNode.checkSupport(extensions.toList(), ownLeaf)

  val keySchedule = KeyScheduleImpl.new(keyPackage.cipherSuite)
  val tree = RatchetTree.new(keyPackage.cipherSuite, keyPackage.leafNode, keyPackage.encPrivateKey)

  return GroupState.Active(
    GroupContext.new(protocolVersion, cipherSuite, keySchedule, tree, *extensions, groupId = groupId),
    tree,
    keySchedule,
    keyPackage.signingKey,
  )
}

context(Raise<WelcomeJoinError>, AuthenticationService<Identity>)
suspend fun <Identity : Any> Welcome.joinGroup(
  keyPackage: KeyPackage.Private,
  resumptionGroup: GroupState? = null,
  psks: PskLookup = PskLookup.EMPTY,
  optTree: PublicRatchetTree? = null,
): GroupState =
  DecoderError.wrap {
    val encryptedSecrets =
      secrets
        .find { it.newMember.eq(keyPackage.ref) }
        ?: raise(WelcomeJoinError.NoMatchingKeyPackage)

    keyPackage.checkParametersCompatible(this@joinGroup)

    val groupSecrets =
      cipherSuite.decryptWithLabel(
        keyPackage.initKeyPair,
        "Welcome",
        encryptedGroupInfo.value,
        encryptedSecrets.encryptedGroupSecrets,
      ).decodeAs(GroupSecrets.dataT)

    var hasResumptionPsk = false
    val pskSecret =
      with(cipherSuite) {
        groupSecrets.preSharedKeyIds.map {
          if (hasResumptionPsk && it.isProtocolResumption) {
            raise(WelcomeJoinError.MultipleResumptionPsks)
          }

          hasResumptionPsk = hasResumptionPsk || it.isProtocolResumption

          it to psks.getPreSharedKey(it)
        }.calculatePskSecret()
      }

    val welcomeSecret =
      cipherSuite.deriveSecret(
        cipherSuite.extract(groupSecrets.joinerSecret, pskSecret),
        "welcome",
      )

    val welcomeNonce = cipherSuite.expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), cipherSuite.nonceLen).asNonce
    val welcomeKey = cipherSuite.expandWithLabel(welcomeSecret, "key", byteArrayOf(), cipherSuite.keyLen)

    val groupInfo =
      cipherSuite.decryptAead(welcomeKey, welcomeNonce, Aad.empty, encryptedGroupInfo)
        .decodeAs(GroupInfo.dataT)

    val publicTree = groupInfo.extension<RatchetTreeExt>()?.tree ?: optTree ?: raise(JoinError.MissingRatchetTree)
    with(cipherSuite) {
      groupInfo.verifySignature(publicTree)
      publicTree.check(groupInfo.groupContext)
    }

    val ownLeaf = publicTree.findEquivalentLeaf(keyPackage) ?: raise(WelcomeJoinError.OwnLeafNotFound)
    var tree = publicTree.join(cipherSuite, ownLeaf, keyPackage.encPrivateKey)

    var groupContext = groupInfo.groupContext

    keyPackage.leafNode.checkSupport(groupContext.extensions, ownLeaf)

    tree =
      groupSecrets.pathSecret.map {
        with(cipherSuite) { tree.updateOnJoin(ownLeaf, groupInfo.signer, it) }
      }.getOrElse { tree }

    val keySchedule =
      KeySchedule.join(
        cipherSuite,
        groupSecrets.joinerSecret,
        pskSecret,
        groupContext.epoch,
        tree.leaves.uSize,
        groupContext,
      )

    cipherSuite.verifyMac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash, groupInfo.confirmationTag)
    groupContext = with(cipherSuite) { groupContext.withInterimTranscriptHash(groupInfo.confirmationTag) }

    if (hasResumptionPsk) {
      if (groupContext.epoch != 1UL) raise(WelcomeJoinError.WrongResumptionEpoch(groupContext.epoch))
      val resumptionPsk =
        groupSecrets.preSharedKeyIds
          .filterIsInstance<ResumptionPskId>()
          .first()

      validateResumption(
        groupContext,
        tree,
        resumptionPsk,
        resumptionGroup ?: raise(WelcomeJoinError.MissingResumptionGroup(resumptionPsk)),
      )
    }

    GroupState.Active(groupContext, tree, keySchedule, keyPackage.signingKey)
  }

context(Raise<ExternalJoinError>, AuthenticationService<Identity>)
suspend fun <Identity : Any> GroupInfo.joinGroupExternal(
  keyPackage: KeyPackage.Private,
  resync: Boolean = false,
  authenticatedData: ByteArray = byteArrayOf(),
): Pair<GroupState, MlsMessage<PublicMessage<Commit>>> {
  keyPackage.checkParametersCompatible(this)

  val cipherSuite = groupContext.cipherSuite

  val externalPub = extension<ExternalPub>()?.externalPub ?: raise(ExternalJoinError.MissingExternalPub)
  val (kemOutput, externalInitSecret) = cipherSuite.export(externalPub, "")

  var publicTree = extension<RatchetTreeExt>()?.tree ?: raise(JoinError.MissingRatchetTree)
  with(cipherSuite) { verifySignature(publicTree) }
  publicTree.check(groupContext)

  val oldLeafIdx = if (resync) publicTree.findEquivalentLeaf(keyPackage.leafNode) else null
  if (oldLeafIdx != null) publicTree -= oldLeafIdx

  val newTree = publicTree.insert(cipherSuite, keyPackage.leafNode, keyPackage.encPrivateKey)

  keyPackage.leafNode.checkSupport(groupContext.extensions, newTree.leafIndex)

  var groupContext = with(cipherSuite) { groupContext.withInterimTranscriptHash(confirmationTag) }

  val (updatedTree, updatePath, pathSecrets) =
    createUpdatePath(newTree, setOf(), groupContext, keyPackage.signingKey)

  val commitSecret = cipherSuite.deriveSecret(pathSecrets.last(), "path")

  val proposals =
    listOfNotNull(
      oldLeafIdx?.let { Remove(oldLeafIdx) },
      ExternalInit(kemOutput),
    )
  val framedContent =
    FramedContent(
      groupContext.groupId,
      groupContext.epoch,
      Sender.newMemberCommit(),
      authenticatedData,
      Commit(proposals, updatePath),
    )
  val signature =
    with(cipherSuite) {
      framedContent.sign(WireFormat.MlsPublicMessage, groupContext, keyPackage.signingKey)
    }

  groupContext =
    with(cipherSuite) {
      groupContext.evolve(WireFormat.MlsPublicMessage, framedContent, signature, updatedTree)
    }

  val pskSecret = with(cipherSuite) { listOf<Pair<PreSharedKeyId, Secret>>().calculatePskSecret() }

  val keySchedule =
    KeySchedule.joinExternal(
      cipherSuite,
      externalInitSecret,
      commitSecret,
      pskSecret,
      groupContext.epoch,
      updatedTree.leaves.uSize,
      groupContext,
    )

  val confirmationTag = cipherSuite.mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash)

  groupContext = with(cipherSuite) { groupContext.withInterimTranscriptHash(confirmationTag) }

  return GroupState.Active(
    groupContext,
    updatedTree,
    keySchedule,
    keyPackage.signingKey,
  ) to
    with(cipherSuite) {
      with(keySchedule) {
        MlsMessage.public(
          AuthenticatedContent(WireFormat.MlsPublicMessage, framedContent, signature, confirmationTag),
          groupContext,
        )
      }
    }
}

context(Raise<ExtensionSupportError>)
private fun KeyPackageLeafNode.checkSupport(
  extensions: GroupContextExtensions,
  ownLeaf: LeafIndex,
) {
  // Check that own leaf node is compatible with group requirements
  extensions.filterIsInstance<RequiredCapabilities>().firstOrNull()?.let { requiredCapabilities ->
    if (!requiredCapabilities.isCompatible(capabilities)) {
      raise(
        LeafNodeCheckError.UnsupportedCapabilities(
          ownLeaf,
          requiredCapabilities,
          capabilities,
        ),
      )
    }
  }

  // Check that own leaf noe is compatible with current group context extensions
  extensions
    .filterNot { capabilities supportsExtension it.type }
    .takeIf { it.isNotEmpty() }
    ?.let { unsupportedExtensions ->
      raise(
        ExtensionSupportError.UnsupportedGroupContextExtensions(
          capabilities,
          unsupportedExtensions,
        ),
      )
    }
}
