package com.github.traderjoe95.mls.protocol.group

import arrow.core.getOrElse
import arrow.core.nonEmptyListOf
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
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
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.insert
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.join
import com.github.traderjoe95.mls.protocol.tree.check
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.findEquivalentLeaf
import com.github.traderjoe95.mls.protocol.tree.updateOnJoin
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.RatchetTree
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.ExternalPskId
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
import com.github.traderjoe95.mls.protocol.types.framing.message.PublicMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import de.traderjoe.ulid.ULID

context(Raise<GroupCreationError>)
suspend fun <Identity : Any> ApplicationCtx<Identity>.newGroup(
  cipherSuite: CipherSuite,
  vararg extensions: GroupContextExtension<*>,
  protocolVersion: ProtocolVersion = ProtocolVersion.MLS_1_0,
  groupId: ULID? = null,
  keepPastEpochs: UInt = 5U,
): GroupState {
  val (keyPackage, _, encryptionKeyPair, signingKey) = newKeyPackage(cipherSuite)
  val ownLeaf = LeafIndex(0U)

  keyPackage.leafNode.checkSupport(extensions.toList(), ownLeaf)

  return ActiveGroupState(
    GroupSettings.new(cipherSuite, protocolVersion, groupId, keepPastEpochs),
    nonEmptyListOf(GroupEpoch.init(keyPackage, encryptionKeyPair, *extensions)),
    signingKey,
  )
}

context(Raise<WelcomeJoinError>)
suspend fun <Identity : Any> ApplicationCtx<Identity>.joinGroup(
  welcome: Welcome,
  keepPastEpochs: UInt = 5U,
): GroupState =
  DecoderError.wrap {
    val cipherSuite = welcome.cipherSuite

    val (encryptedSecrets, ownKeyPackage) =
      welcome.secrets.map { encryptedSecrets ->
        encryptedSecrets to getKeyPackage(encryptedSecrets.newMember)
      }.find { it.second != null } ?: raise(WelcomeJoinError.NoMatchingKeyPackage)
    val (keyPackage, ownInitKeyPair, ownEncKeyPair, ownSigningKey) = ownKeyPackage!!

    if (keyPackage.cipherSuite != cipherSuite) {
      raise(WelcomeJoinError.WrongCipherSuite(keyPackage.cipherSuite, cipherSuite))
    }

    val groupSecrets =
      cipherSuite.decryptWithLabel(
        ownInitKeyPair,
        "Welcome",
        welcome.encryptedGroupInfo.value,
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

          it to
            when (it) {
              is ExternalPskId -> getExternalPsk(it.pskId)
              is ResumptionPskId -> getResumptionPsk(it.pskGroupId, it.pskEpoch)
            }
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
      cipherSuite.decryptAead(welcomeKey, welcomeNonce, Aad.empty, welcome.encryptedGroupInfo)
        .decodeAs(GroupInfo.dataT)

    if (groupIdExists(groupInfo.groupContext.groupId)) raise(JoinError.AlreadyMember)

    val publicTree = groupInfo.extension<RatchetTree>()?.tree ?: raise(JoinError.MissingRatchetTree)
    with(cipherSuite) {
      groupInfo.verifySignature(publicTree)
      publicTree.check(groupInfo.groupContext)
    }

    val ownLeaf = publicTree.findEquivalentLeaf(keyPackage) ?: raise(WelcomeJoinError.OwnLeafNotFound)
    var tree = publicTree.join(welcome.cipherSuite, ownLeaf, ownEncKeyPair.private)

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

      validateResumption(groupContext, tree, resumptionPsk)
    }

    ActiveGroupState(
      groupContext.settings(keepPastEpochs = keepPastEpochs),
      nonEmptyListOf(
        GroupEpoch(
          groupContext.epoch,
          tree,
          keySchedule,
          groupContext.confirmedTranscriptHash,
          groupContext.extensions,
          groupContext.interimTranscriptHash,
          Commit.empty,
          cipherSuite.mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash),
        ),
      ),
      ownSigningKey,
    )
  }

context(Raise<ExternalJoinError>)
suspend fun <Identity : Any> ApplicationCtx<Identity>.joinGroupExternal(
  groupInfo: GroupInfo,
  resync: Boolean = false,
  authenticatedData: ByteArray = byteArrayOf(),
  keepPastEpochs: UInt = 5U,
): Pair<GroupState, MlsMessage<PublicMessage<Commit>>> {
  val cipherSuite = groupInfo.groupContext.cipherSuite

  val (keyPackage, _, ownEncryptionKeyPair, ownSigningKey) = newKeyPackage(cipherSuite)

  val externalPub = groupInfo.extension<ExternalPub>()?.externalPub ?: raise(ExternalJoinError.MissingExternalPub)
  val (kemOutput, externalInitSecret) = cipherSuite.export(externalPub, "")

  if (groupIdExists(groupInfo.groupContext.groupId)) raise(JoinError.AlreadyMember)

  var publicTree = groupInfo.extension<RatchetTree>()?.tree ?: raise(JoinError.MissingRatchetTree)
  with(cipherSuite) { groupInfo.verifySignature(publicTree) }
  with(cipherSuite) { publicTree.check(groupInfo.groupContext) }

  val oldLeafIdx = if (resync) publicTree.findEquivalentLeaf(keyPackage.leafNode) else null
  if (oldLeafIdx != null) publicTree -= oldLeafIdx

  val newTree = publicTree.insert(cipherSuite, keyPackage.leafNode, ownEncryptionKeyPair.private)

  keyPackage.leafNode.checkSupport(groupInfo.groupContext.extensions, newTree.leafIndex)

  var groupContext = with(cipherSuite) { groupInfo.groupContext.withInterimTranscriptHash(groupInfo.confirmationTag) }

  val (updatedTree, updatePath, pathSecrets) =
    with(cipherSuite) {
      createUpdatePath(newTree, setOf(), groupContext, ownSigningKey)
    }

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
  val signature = with(cipherSuite) { framedContent.sign(WireFormat.MlsPublicMessage, groupContext, ownSigningKey) }

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

  return ActiveGroupState(
    groupContext.settings(keepPastEpochs),
    nonEmptyListOf(
      GroupEpoch(
        groupContext.epoch,
        updatedTree,
        keySchedule,
        groupContext.confirmedTranscriptHash,
        groupContext.extensions,
        groupContext.interimTranscriptHash,
        Commit.empty,
        cipherSuite.mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash),
      ),
    ),
    ownSigningKey,
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
