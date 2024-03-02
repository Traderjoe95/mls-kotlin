package com.github.traderjoe95.mls.protocol.group

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.ExtensionSupportError
import com.github.traderjoe95.mls.protocol.error.ExternalJoinError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.resumption.isProtocolResumption
import com.github.traderjoe95.mls.protocol.group.resumption.validateResumption
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.PublicMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.psk.ResolvedPsk
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.insert
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.join
import com.github.traderjoe95.mls.protocol.tree.check
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.findEquivalentLeaf
import com.github.traderjoe95.mls.protocol.tree.insertPathSecrets
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import com.github.traderjoe95.mls.protocol.types.RatchetTree as RatchetTreeExt

fun newGroup(
  keyPackage: KeyPackage.Private,
  vararg extensions: GroupContextExtension<*>,
  protocolVersion: ProtocolVersion = keyPackage.version,
  cipherSuite: CipherSuite = keyPackage.cipherSuite,
  groupId: GroupId? = null,
): Either<GroupCreationError, GroupState.Active> =
  either {
    keyPackage.checkParametersCompatible(protocolVersion, cipherSuite)

    val ownLeaf = LeafIndex(0U)

    keyPackage.leafNode.checkSupport(extensions.toList(), ownLeaf)

    val tree = RatchetTree.new(keyPackage.cipherSuite, keyPackage.leafNode, keyPackage.encPrivateKey)
    val groupContext = GroupContext.new(protocolVersion, cipherSuite, tree, *extensions, groupId = groupId)
    val keySchedule = KeySchedule.init(keyPackage.cipherSuite, groupContext)

    GroupState.Active(
      groupContext.withInterimTranscriptHash(
        newInterimTranscriptHash(
          keyPackage.cipherSuite,
          groupContext.confirmedTranscriptHash,
          cipherSuite.mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash),
        ),
      ),
      tree,
      keySchedule,
      keyPackage.signaturePrivateKey,
    )
  }

suspend fun <Identity : Any> Welcome.joinGroup(
  keyPackage: KeyPackage.Private,
  authenticationService: AuthenticationService<Identity>,
  resumingFrom: GroupState? = null,
  psks: PskLookup = PskLookup.EMPTY,
  optionalTree: PublicRatchetTree? = null,
): Either<WelcomeJoinError, GroupState> =
  either {
    DecoderError.wrap {
      keyPackage.checkParametersCompatible(this@joinGroup)

      val groupSecrets = decryptGroupSecrets(keyPackage).bind()

      val hasResumptionPsk =
        when (groupSecrets.preSharedKeyIds.count { it.isProtocolResumption }) {
          1 -> true
          0 -> false
          else -> raise(WelcomeJoinError.MultipleResumptionPsks)
        }

      val resolvedPsks = PskLookup.resolvePsks(psks, groupSecrets.preSharedKeyIds).bind()
      val pskSecret = ResolvedPsk.calculatePskSecret(cipherSuite, resolvedPsks)

      val groupInfo = decryptGroupInfo(groupSecrets.joinerSecret, pskSecret).bind()

      val publicTree =
        groupInfo.extension<RatchetTreeExt>()?.tree ?: optionalTree ?: raise(JoinError.MissingRatchetTree)

      groupInfo.verifySignature(publicTree).bind()
      publicTree.check(groupInfo.groupContext).bind()

      val ownLeaf = publicTree.findEquivalentLeaf(keyPackage) ?: raise(WelcomeJoinError.OwnLeafNotFound)
      var tree = publicTree.join(cipherSuite, ownLeaf, keyPackage.encPrivateKey)

      var groupContext = groupInfo.groupContext

      keyPackage.leafNode.checkSupport(groupContext.extensions, ownLeaf)

      tree =
        groupSecrets.pathSecret.map {
          with(cipherSuite) { tree.insertPathSecrets(ownLeaf, groupInfo.signer, it) }
        }.getOrElse { tree }

      val keySchedule =
        KeySchedule.join(
          cipherSuite,
          groupSecrets.joinerSecret,
          pskSecret,
          groupContext,
        )

      cipherSuite.verifyMac(
        keySchedule.confirmationKey,
        groupContext.confirmedTranscriptHash,
        groupInfo.confirmationTag,
      )
      groupContext =
        groupContext.withInterimTranscriptHash(
          newInterimTranscriptHash(
            cipherSuite,
            groupContext.confirmedTranscriptHash,
            groupInfo.confirmationTag,
          ),
        )

      if (hasResumptionPsk) {
        if (groupContext.epoch != 1UL) raise(WelcomeJoinError.WrongResumptionEpoch(groupContext.epoch))
        val resumptionPsk =
          groupSecrets.preSharedKeyIds
            .filterIsInstance<ResumptionPskId>()
            .first()

        with(authenticationService) {
          validateResumption(
            groupContext,
            tree,
            resumptionPsk,
            resumingFrom ?: raise(WelcomeJoinError.MissingResumptionGroup(resumptionPsk)),
          )
        }
      }

      GroupState.Active(groupContext, tree, keySchedule, keyPackage.signaturePrivateKey)
    }
  }

suspend fun <Identity : Any> GroupInfo.joinGroupExternal(
  keyPackage: KeyPackage.Private,
  authenticationService: AuthenticationService<Identity>,
  resync: Boolean = false,
  authenticatedData: ByteArray = byteArrayOf(),
  optionalTree: PublicRatchetTree? = null,
): Either<ExternalJoinError, Pair<GroupState, MlsMessage<PublicMessage<Commit>>>> =
  either {
    keyPackage.checkParametersCompatible(this@joinGroupExternal)

    val cipherSuite = groupContext.cipherSuite

    val externalPub = extension<ExternalPub>()?.externalPub ?: raise(ExternalJoinError.MissingExternalPub)
    val (kemOutput, externalInitSecret) = cipherSuite.export(externalPub, "").bind()

    var publicTree = extension<RatchetTreeExt>()?.tree ?: optionalTree ?: raise(JoinError.MissingRatchetTree)

    verifySignature(publicTree).bind()
    publicTree.check(groupContext).bind()

    val oldLeafIdx =
      if (resync) with(authenticationService) { publicTree.findEquivalentLeaf(keyPackage.leafNode) } else null
    if (oldLeafIdx != null) publicTree = publicTree.remove(oldLeafIdx)

    val newTree = publicTree.insert(cipherSuite, keyPackage.leafNode, keyPackage.encPrivateKey)

    keyPackage.leafNode.checkSupport(groupContext.extensions, newTree.leafIndex)

    var groupContext =
      groupContext.withInterimTranscriptHash(
        newInterimTranscriptHash(
          cipherSuite,
          groupContext.confirmedTranscriptHash,
          confirmationTag,
        ),
      )

    val (updatedTree, updatePath, pathSecrets) =
      createUpdatePath(newTree, setOf(), groupContext, keyPackage.signaturePrivateKey)

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
    val signature = framedContent.sign(WireFormat.MlsPublicMessage, groupContext, keyPackage.signaturePrivateKey).bind()

    groupContext = groupContext.evolve(WireFormat.MlsPublicMessage, framedContent, signature, updatedTree)

    val pskSecret = ResolvedPsk.calculatePskSecret(cipherSuite, listOf())

    val keySchedule =
      KeySchedule.init(
        cipherSuite,
        groupContext,
        initSecret = externalInitSecret,
        commitSecret = commitSecret,
        pskSecret = pskSecret,
      )

    val confirmationTag = cipherSuite.mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash)

    groupContext =
      groupContext.withInterimTranscriptHash(
        newInterimTranscriptHash(
          cipherSuite,
          groupContext.confirmedTranscriptHash,
          confirmationTag,
        ),
      )

    GroupState.Active(
      groupContext,
      updatedTree,
      keySchedule,
      keyPackage.signaturePrivateKey,
    ).let { state ->
      state to
        state.messages.protectPublic(
          AuthenticatedContent(
            WireFormat.MlsPublicMessage,
            framedContent,
            signature,
            confirmationTag,
          ),
        )
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
