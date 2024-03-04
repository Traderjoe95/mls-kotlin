package com.github.traderjoe95.mls.protocol.group

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.nullable
import arrow.core.right
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.AddValidationError
import com.github.traderjoe95.mls.protocol.error.GroupContextExtensionsValidationError
import com.github.traderjoe95.mls.protocol.error.KeyPackageValidationError
import com.github.traderjoe95.mls.protocol.error.LeafNodeCheckError
import com.github.traderjoe95.mls.protocol.error.PreSharedKeyValidationError
import com.github.traderjoe95.mls.protocol.error.ProposalValidationError
import com.github.traderjoe95.mls.protocol.error.ProposalValidationError.BadExternalProposal
import com.github.traderjoe95.mls.protocol.error.ReInitValidationError
import com.github.traderjoe95.mls.protocol.error.RemoveValidationError
import com.github.traderjoe95.mls.protocol.error.UnexpectedExtension
import com.github.traderjoe95.mls.protocol.error.UpdateValidationError
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTreeOps
import com.github.traderjoe95.mls.protocol.tree.validate
import com.github.traderjoe95.mls.protocol.tree.zipWithLeafIndex
import com.github.traderjoe95.mls.protocol.types.ExtensionType
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import com.github.traderjoe95.mls.protocol.util.filterInternalNulls
import com.github.traderjoe95.mls.protocol.util.mapNoInternalNulls

class Validations(
  private val groupContext: GroupContext,
  private val currentTree: RatchetTreeOps,
) {
  internal constructor(groupState: GroupState.Active) : this(
    groupState.groupContext,
    groupState.tree,
  )

  private val protocolVersion: ProtocolVersion
    get() = groupContext.protocolVersion
  private val cipherSuite: CipherSuite
    get() = groupContext.cipherSuite

  fun validated(
    keyPackage: KeyPackage,
    currentTree: RatchetTreeOps = this.currentTree,
  ): Either<KeyPackageValidationError, KeyPackage> =
    either {
      ensure(keyPackage.version == protocolVersion) {
        KeyPackageValidationError.IncompatibleProtocolVersion(keyPackage.version, protocolVersion)
      }

      ensure(keyPackage.cipherSuite == cipherSuite) {
        KeyPackageValidationError.IncompatibleCipherSuite(keyPackage.cipherSuite, cipherSuite)
      }

      keyPackage.leafNode.validate(
        currentTree,
        groupContext,
        currentTree.firstBlankLeaf ?: (currentTree.leafNodeIndices.last + 2U).leafIndex,
        LeafNodeSource.KeyPackage,
      )

      keyPackage.verifySignature().bind()

      ensure(keyPackage.initKey neq keyPackage.leafNode.encryptionKey) {
        KeyPackageValidationError.InitKeyReuseAsEncryptionKey(keyPackage)
      }

      keyPackage
    }

  suspend fun validated(proposal: AuthenticatedContent<Proposal>): Either<ProposalValidationError, AuthenticatedContent<Proposal>> =
    either {
      proposal.apply { validated(framedContent.content, sender).bind() }
    }

  suspend fun validated(
    proposal: Proposal,
    sender: Sender,
  ): Either<ProposalValidationError, Proposal> =
    either {
      when (sender.type) {
        SenderType.External ->
          if (proposal.type !in ProposalType.EXTERNAL_SENDER) {
            raise(
              BadExternalProposal(
                proposal.type,
                SenderType.External,
              ),
            )
          } else {
            validated(proposal, null).bind()
          }

        SenderType.NewMemberProposal ->
          if (proposal.type != ProposalType.Add) {
            raise(BadExternalProposal(proposal.type, SenderType.NewMemberProposal))
          } else {
            validated(proposal as Add).bind()
          }

        SenderType.NewMemberCommit -> raise(BadExternalProposal(proposal.type, SenderType.NewMemberCommit))
        SenderType.Member -> validated(proposal, sender.index!!).bind()

        else -> raise(BadExternalProposal(proposal.type, sender.type))
      }
    }

  private suspend fun validated(
    proposal: Proposal,
    sender: LeafIndex?,
  ): Either<ProposalValidationError, Proposal> =
    when (proposal) {
      is Add -> validated(proposal)
      is Update -> validated(proposal, sender!!)
      is Remove -> validated(proposal)
      is PreSharedKey -> validated(proposal).map { proposal }
      is ReInit -> validated(proposal)
      is GroupContextExtensions -> validated(proposal)
      else -> proposal.right()
    }

  fun validated(
    add: Add,
    currentTree: RatchetTreeOps = this.currentTree,
  ): Either<AddValidationError, Add> =
    either {
      add.apply { validated(keyPackage, currentTree).bind() }
    }

  fun validated(
    update: Update,
    generatedBy: LeafIndex,
    currentTree: RatchetTreeOps = this.currentTree,
  ): Either<UpdateValidationError, Update> =
    either {
      update.apply { leafNode.validate(currentTree, groupContext, generatedBy, LeafNodeSource.Update) }
    }

  fun validated(
    remove: Remove,
    currentTree: RatchetTreeOps = this.currentTree,
  ): Either<RemoveValidationError, Remove> =
    either {
      remove.apply {
        if (currentTree[removed] == null) raise(RemoveValidationError.BlankLeafRemoved(removed))
      }
    }

  suspend fun validated(
    preSharedKey: PreSharedKey,
    psks: PskLookup? = null,
    inReInit: Boolean = false,
    inBranch: Boolean = false,
  ): Either<PreSharedKeyValidationError, Secret?> =
    either {
      preSharedKey.pskId.validate(cipherSuite, inReInit, inBranch)

      psks?.getPreSharedKey(preSharedKey.pskId)?.bind()
    }

  fun validated(reInit: ReInit): Either<ReInitValidationError, ReInit> =
    either {
      if (reInit.protocolVersion < protocolVersion) {
        raise(ReInitValidationError.ReInitDowngrade(protocolVersion, protocolVersion))
      }

      reInit.extensions.find { it !is GroupContextExtension<*> }?.also {
        raise(
          UnexpectedExtension(
            "GroupContext",
            it.extensionType?.toString() ?: it.type.toString(),
          ),
        )
      }

      reInit
    }

  fun validated(
    groupContextExtensions: GroupContextExtensions,
    currentTree: RatchetTreeOps = this.currentTree,
    removed: Set<LeafIndex> = setOf(),
  ): Either<GroupContextExtensionsValidationError, GroupContextExtensions> =
    either {
      val extTypes = groupContextExtensions.extensions.map { it.type }
      currentTree.leaves
        .zipWithLeafIndex()
        .filter { it.second !in removed }
        .filterInternalNulls()
        .mapNoInternalNulls { (node, index) ->
          index to extTypes.filterNot { node.capabilities.supportsExtension(it) }.takeIf { it.isNotEmpty() }
        }
        .firstOrNull()
        ?.also { (leafIndex, unsupportedExt) ->
          raise(
            LeafNodeCheckError.UnsupportedExtensions(
              leafIndex,
              unsupportedExt.map { ExtensionType(it) ?: it }.toSet(),
            ),
          )
        }

      groupContextExtensions.extension<RequiredCapabilities>()?.let { required ->
        currentTree.leaves
          .zipWithLeafIndex()
          .mapNotNull {
            nullable { it.first.bind() to it.second }
          }
          .filterNot { (leaf, leafIdx) -> leafIdx in removed || required.isCompatible(leaf.capabilities) }
          .onEach { (leaf, leafIdx) ->
            raise(LeafNodeCheckError.UnsupportedCapabilities(leafIdx, required, leaf.capabilities))
          }
      }

      groupContextExtensions
    }
}
