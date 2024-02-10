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
import com.github.traderjoe95.mls.protocol.error.BranchJoinError
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.ExtensionSupportError
import com.github.traderjoe95.mls.protocol.error.ExternalJoinError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.error.ReInitJoinError
import com.github.traderjoe95.mls.protocol.error.ResumptionJoinError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.tree.LeafNodeRecord
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.check
import com.github.traderjoe95.mls.protocol.tree.findEquivalentLeaf
import com.github.traderjoe95.mls.protocol.tree.leafNode
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafNodes
import com.github.traderjoe95.mls.protocol.tree.updateOnJoin
import com.github.traderjoe95.mls.protocol.tree.updatePath
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.RatchetTreeExt
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.ExternalPskId
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskUsage
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
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
  public: Boolean = false,
  keepPastEpochs: UInt = 5U,
): GroupState {
  val (keyPackage, hpkeKeyPair, signingKey) = newKeyPackage(cipherSuite)

  keyPackage.leafNode.checkSupport(extensions.toList(), 0U)

  return GroupStateImpl(
    GroupSettings.new(cipherSuite, protocolVersion, groupId, keepPastEpochs, public),
    nonEmptyListOf(GroupEpoch.init(keyPackage, hpkeKeyPair, *extensions)),
    signingKey,
    0U,
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
    val (keyPackage, ownInitKeyPair, ownSigningKey) = ownKeyPackage!!

    if (keyPackage.cipherSuite != cipherSuite) {
      raise(WelcomeJoinError.WrongCipherSuite(keyPackage.cipherSuite, cipherSuite))
    }

    val groupSecrets =
      EncoderError.wrap {
        cipherSuite.decryptWithLabel(
          ownInitKeyPair,
          "Welcome",
          welcome.encryptedGroupInfo.value,
          encryptedSecrets.encryptedGroupSecrets,
        )
      }.decodeAs(GroupSecrets.T)

    var hasResumptionPsk = false
    val pskSecret =
      with(cipherSuite) {
        EncoderError.wrap {
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
      }

    val (welcomeNonce, welcomeKey) =
      EncoderError.wrap {
        val welcomeSecret =
          cipherSuite.deriveSecret(
            cipherSuite.extract(groupSecrets.joinerSecret, pskSecret),
            "welcome",
          )

        val welcomeNonce =
          cipherSuite.expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), cipherSuite.nonceLen).asNonce
        val welcomeKey = cipherSuite.expandWithLabel(welcomeSecret, "key", byteArrayOf(), cipherSuite.keyLen)

        welcomeNonce to welcomeKey
      }

    val groupInfo =
      cipherSuite.decryptAead(welcomeKey, welcomeNonce, Aad.empty, welcome.encryptedGroupInfo)
        .decodeAs(GroupInfo.T)
    var tree = groupInfo.extension<RatchetTreeExt>()?.tree ?: raise(JoinError.MissingRatchetTree)
    with(cipherSuite) { groupInfo.verifySignature(tree) }

    if (groupIdExists(groupInfo.groupContext.groupId)) raise(JoinError.AlreadyMember)
    with(cipherSuite) { tree.check(groupInfo.groupContext) }

    val ownLeaf = tree.findEquivalentLeaf(keyPackage) ?: raise(WelcomeJoinError.OwnLeafNotFound)

    var groupContext = groupInfo.groupContext

    keyPackage.leafNode.checkSupport(groupContext.extensions, ownLeaf)

    tree[ownLeaf] = LeafNodeRecord(tree.leafNode(ownLeaf) to ownInitKeyPair.private)

    tree =
      groupSecrets.pathSecret.map {
        with(cipherSuite) { tree.updateOnJoin(ownLeaf, groupInfo.signer * 2U, it) }
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
    groupContext =
      EncoderError.wrap {
        with(cipherSuite) { groupContext.withInterimTranscriptHash(groupInfo.confirmationTag) }
      }

    if (hasResumptionPsk) {
      if (groupContext.epoch != 1UL) raise(WelcomeJoinError.WrongResumptionEpoch(groupContext.epoch))
      val resumptionPsk =
        groupSecrets.preSharedKeyIds
          .filterIsInstance<ResumptionPskId>()
          .first()

      validateResumption(groupContext, tree, resumptionPsk)
    }

    GroupStateImpl(
      groupContext.settings(keepPastEpochs = keepPastEpochs, public = groupInfo.hasExtension<ExternalPub>()),
      nonEmptyListOf(
        GroupEpoch(
          groupContext.epoch,
          tree,
          keySchedule,
          groupContext.confirmedTranscriptHash,
          groupContext.extensions,
          groupContext.interimTranscriptHash,
          Commit.empty,
        ),
      ),
      ownSigningKey,
      ownLeaf,
    )
  }

context(Raise<ExternalJoinError>)
suspend fun <Identity : Any> ApplicationCtx<Identity>.joinGroupExternal(
  groupInfo: GroupInfo,
  resync: Boolean = false,
  authenticatedData: ByteArray = byteArrayOf(),
  keepPastEpochs: UInt = 5U,
): Pair<GroupState, MlsMessage<PublicMessage<Commit>>> =
  EncoderError.wrap {
    val cipherSuite = groupInfo.groupContext.cipherSuite

    val (keyPackage, ownInitKeyPair, ownSigningKey) = newKeyPackage(cipherSuite)

    val externalPub = groupInfo.extension<ExternalPub>()?.externalPub ?: raise(ExternalJoinError.MissingExternalPub)
    val (kemOutput, externalInitSecret) = cipherSuite.export(externalPub, "")

    if (groupIdExists(groupInfo.groupContext.groupId)) raise(JoinError.AlreadyMember)

    var tree = groupInfo.extension<RatchetTreeExt>()?.tree ?: raise(JoinError.MissingRatchetTree)
    with(cipherSuite) { groupInfo.verifySignature(tree) }
    with(cipherSuite) { tree.check(groupInfo.groupContext) }

    val oldLeafIdx = if (resync) tree.findEquivalentLeaf(keyPackage.leafNode) else null
    if (oldLeafIdx != null) tree -= oldLeafIdx / 2U

    val (newTree, ownLeaf) =
      tree.insert(LeafNodeRecord(keyPackage.leafNode to ownInitKeyPair.private))

    keyPackage.leafNode.checkSupport(groupInfo.groupContext.extensions, ownLeaf)

    var groupContext = with(cipherSuite) { groupInfo.groupContext.withInterimTranscriptHash(groupInfo.confirmationTag) }

    val (updatedTree, updatePath, pathSecrets) =
      with(cipherSuite) {
        newTree.updatePath(setOf(), ownLeaf, groupContext, ownSigningKey)
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
    val signature = with(cipherSuite) { framedContent.sign(WireFormat.MlsPrivateMessage, groupContext, ownSigningKey) }

    groupContext =
      with(cipherSuite) { groupContext.evolve(WireFormat.MlsPrivateMessage, framedContent, signature, updatedTree) }

    val pskSecret = with(cipherSuite) { listOf<Pair<PreSharedKeyId, Secret>>().calculatePskSecret() }

    val keySchedule =
      KeySchedule.joinExternal(
        cipherSuite,
        externalInitSecret,
        commitSecret,
        pskSecret,
        groupContext.epoch,
        tree.leaves.uSize,
        groupContext,
      )

    val confirmationTag = cipherSuite.mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash)

    groupContext =
      EncoderError.wrap {
        with(cipherSuite) { groupContext.withInterimTranscriptHash(confirmationTag) }
      }

    GroupStateImpl(
      groupContext.settings(keepPastEpochs, public = true),
      nonEmptyListOf(
        GroupEpoch(
          groupContext.epoch,
          tree,
          keySchedule,
          groupContext.confirmedTranscriptHash,
          groupContext.extensions,
          groupContext.interimTranscriptHash,
          Commit.empty,
        ),
      ),
      ownSigningKey,
      ownLeaf,
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
private fun KeyPackageLeafNode.checkSupport(extensions: GroupContextExtensions, ownLeaf: UInt) {
  // Check that own leaf node is compatible with group requirements
  extensions.filterIsInstance<RequiredCapabilities>().firstOrNull()?.let { requiredCapabilities ->
    if (!requiredCapabilities.isCompatible(capabilities)) {
      raise(
        LeafNodeCheckError.UnsupportedCapabilities(
          ownLeaf,
          requiredCapabilities,
          capabilities
        )
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
          unsupportedExtensions
        )
      )
    }
}

private val PreSharedKeyId.isProtocolResumption: Boolean
  get() = this is ResumptionPskId && usage in ResumptionPskUsage.PROTOCOL_RESUMPTION

context(Raise<WelcomeJoinError>)
private suspend fun <Identity : Any> ApplicationCtx<Identity>.validateResumption(
  groupContext: GroupContext,
  tree: RatchetTree,
  resumptionPsk: ResumptionPskId,
) = when (resumptionPsk.usage) {
  ResumptionPskUsage.ReInit -> validateReInit(groupContext, tree, resumptionPsk)
  ResumptionPskUsage.Branch -> validateBranch(groupContext, tree, resumptionPsk)
  else -> { /* Nothing to validate */
  }
}

context(Raise<ReInitJoinError>)
private suspend fun <Identity : Any> ApplicationCtx<Identity>.validateReInit(
  groupContext: GroupContext,
  tree: RatchetTree,
  resumptionPsk: ResumptionPskId,
) {
  val evidence = getReInitEvidence(resumptionPsk.pskGroupId)

  if (evidence.currentEpoch != resumptionPsk.pskEpoch) {
    raise(ReInitJoinError.UnexpectedEpoch(evidence.currentEpoch, resumptionPsk.pskEpoch))
  }

  val reInit =
    evidence.lastCommitProposals
      .filterIsInstance<ReInit>()
      .firstOrNull()
      ?: raise(ReInitJoinError.NoReInitProposal)

  when {
    groupContext.groupId != reInit.groupId ->
      raise(ReInitJoinError.GroupIdMismatch(groupContext.groupId, reInit.groupId))

    groupContext.protocolVersion != reInit.protocolVersion ->
      raise(ResumptionJoinError.ProtocolVersionMismatch(groupContext.protocolVersion, reInit.protocolVersion))

    groupContext.cipherSuite != reInit.cipherSuite ->
      raise(ResumptionJoinError.CipherSuiteMismatch(groupContext.cipherSuite, reInit.cipherSuite))

    groupContext.extensions != reInit.extensions ->
      raise(ReInitJoinError.ExtensionsMismatch(groupContext.extensions, reInit.extensions))
  }

  tree.nonBlankLeafNodes.forEach { leafNodeIdx ->
    val leafNode = tree[leafNodeIdx]!!.asLeaf.node

    evidence.members.find { isSameClient(leafNode.credential, it).bind() } ?: raise(ResumptionJoinError.NewMembersAdded)
  }

  if (tree.nonBlankLeafNodes.size < evidence.members.size) {
    raise(ReInitJoinError.MembersMissing)
  }
}

context(Raise<BranchJoinError>)
private suspend fun <Identity : Any> ApplicationCtx<Identity>.validateBranch(
  groupContext: GroupContext,
  tree: RatchetTree,
  resumptionPsk: ResumptionPskId,
) {
  val evidence = getBranchEvidence(resumptionPsk.pskGroupId)

  when {
    groupContext.protocolVersion != evidence.protocolVersion ->
      raise(ResumptionJoinError.ProtocolVersionMismatch(groupContext.protocolVersion, evidence.protocolVersion))

    groupContext.cipherSuite != evidence.cipherSuite ->
      raise(ResumptionJoinError.CipherSuiteMismatch(groupContext.cipherSuite, evidence.cipherSuite))
  }

  tree.nonBlankLeafNodes.forEach { leafNodeIdx ->
    val leafNode = tree[leafNodeIdx]!!.asLeaf.node

    evidence.members.find { isSameClient(leafNode.credential, it).bind() } ?: raise(ResumptionJoinError.NewMembersAdded)
  }
}
