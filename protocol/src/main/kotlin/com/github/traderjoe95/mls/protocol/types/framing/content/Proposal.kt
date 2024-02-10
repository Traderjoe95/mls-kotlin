package com.github.traderjoe95.mls.protocol.types.framing.content

import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.T
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.UpdateLeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import de.traderjoe.ulid.ULID

sealed class Proposal(
  val type: ProposalType,
) : Content, ProposalOrRef {
  final override val contentType: ContentType = ContentType.Proposal
  final override val proposalOrRef: ProposalOrRefType = ProposalOrRefType.Proposal

  open val mayBeExternal: Boolean = false
  open val requiresPath: Boolean = true

  fun evaluationOrder(): Int =
    when (this) {
      is GroupContextExtensions -> 0
      is Update -> 1
      is Remove -> 2
      is Add -> 3
      is PreSharedKey -> 4
      is ExternalInit -> 5
      is ReInit -> 6
    }

  companion object {
    val T: DataType<Proposal> by lazy {
      struct("Proposal") {
        it.field("proposal_type", ProposalType.T)
          .select<Proposal, _>(ProposalType.T, "proposal_type") {
            case(ProposalType.Add).then(Add.T)
              .case(ProposalType.Update).then(Update.T)
              .case(ProposalType.Remove).then(Remove.T)
              .case(ProposalType.Psk).then(PreSharedKey.T)
              .case(ProposalType.ReInit).then(ReInit.T)
              .case(ProposalType.ExternalInit).then(ExternalInit.T)
              .case(ProposalType.GroupContextExtensions).then(GroupContextExtensions.T)
          }
      }.lift({ _, p -> p }, { Struct2(it.type, it) })
    }
  }

  @JvmInline
  value class Ref(val ref: ByteArray) : ProposalOrRef {
    internal val hashCode: Int
      get() = ref.contentHashCode()

    override val proposalOrRef: ProposalOrRefType
      get() = ProposalOrRefType.Reference

    companion object {
      val T: DataType<Ref> =
        HashReference.T.derive(
          { it.asProposalRef },
          { HashReference(it.ref) },
          name = "ProposalRef",
        )
    }
  }
}

data class Add(
  val keyPackage: KeyPackage,
) : Proposal(ProposalType.Add), Struct1T.Shape<KeyPackage> {
  override val mayBeExternal: Boolean = true
  override val requiresPath: Boolean = false

  companion object {
    val T: DataType<Add> =
      struct("Add") {
        it.field("key_package", KeyPackage.T)
      }.lift(::Add)
  }
}

data class Update(
  val leafNode: UpdateLeafNode,
) : Proposal(ProposalType.Update), Struct1T.Shape<UpdateLeafNode> {
  companion object {
    val T: DataType<Update> =
      struct("Update") {
        it.field("leaf_node", LeafNode.t(LeafNodeSource.Update))
      }.lift(::Update)
  }
}

data class Remove(
  val removed: UInt,
) : Proposal(ProposalType.Remove), Struct1T.Shape<UInt> {
  override val mayBeExternal: Boolean = true

  companion object {
    val T: DataType<Remove> =
      struct("Remove") {
        it.field("removed", uint32.asUInt)
      }.lift(::Remove)
  }
}

data class PreSharedKey(
  val pskId: PreSharedKeyId,
) : Proposal(ProposalType.Psk), Struct1T.Shape<PreSharedKeyId> {
  override val mayBeExternal: Boolean = true
  override val requiresPath: Boolean = false

  companion object {
    val T: DataType<PreSharedKey> =
      struct("PreSharedKey") {
        it.field("psk", PreSharedKeyId.T)
      }.lift(::PreSharedKey)
  }
}

data class ReInit(
  val groupId: ULID,
  val protocolVersion: ProtocolVersion,
  val cipherSuite: CipherSuite,
  val extensions: List<GroupContextExtension<*>>,
) : Proposal(ProposalType.ReInit), Struct4T.Shape<ULID, ProtocolVersion, CipherSuite, List<GroupContextExtension<*>>> {
  override val mayBeExternal: Boolean = true
  override val requiresPath: Boolean = false

  companion object {
    val T: DataType<ReInit> =
      struct("ReInit") {
        it.field("group_id", ULID.T)
          .field("version", ProtocolVersion.T)
          .field("cipher_suite", CipherSuite.T)
          .field("extensions", GroupContextExtension.T.extensionList())
      }.lift(::ReInit)
  }
}

data class ExternalInit(
  val kemOutput: KemOutput,
) : Proposal(ProposalType.ExternalInit), Struct1T.Shape<KemOutput> {
  companion object {
    val T: DataType<ExternalInit> =
      struct("ExternalInit") {
        it.field("kem_output", KemOutput.T)
      }.lift(::ExternalInit)
  }
}

data class GroupContextExtensions(
  val extensions: List<GroupContextExtension<*>>,
) : Proposal(ProposalType.GroupContextExtensions),
  Struct1T.Shape<List<GroupContextExtension<*>>> {
  override val mayBeExternal: Boolean = true

  inline fun <reified T : GroupContextExtension<*>> extension(): T? = extensions.filterIsInstance<T>().firstOrNull()

  companion object {
    val T: DataType<GroupContextExtensions> =
      struct("GroupContextExtensions") {
        it.field("extensions", GroupContextExtension.T.extensionList())
      }.lift(::GroupContextExtensions)
  }
}
