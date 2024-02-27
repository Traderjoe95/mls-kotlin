package com.github.traderjoe95.mls.protocol.types.framing.content

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode

sealed class Proposal(
  val type: ProposalType,
) : Content.Handshake<Proposal>, ProposalOrRef {
  final override val contentType: ContentType.Proposal = ContentType.Proposal
  final override val proposalOrRef: ProposalOrRefType = ProposalOrRefType.Proposal

  open val mayBeExternal: Boolean = false
  open val requiresPath: Boolean = true

  companion object : Encodable<Proposal> {
    override val dataT: DataType<Proposal> by lazy {
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
  value class Ref(override val bytes: ByteArray) : ProposalOrRef, RefinedBytes<Ref> {
    override val proposalOrRef: ProposalOrRefType
      get() = ProposalOrRefType.Reference

    override val hashCode: Int
      get() = bytes.contentHashCode()

    companion object {
      val T: DataType<Ref> = RefinedBytes.dataT(::Ref, name = "ProposalRef")
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
        it.field("key_package", KeyPackage.dataT)
      }.lift(::Add)
  }
}

data class Update(
  val leafNode: LeafNode<*>,
) : Proposal(ProposalType.Update), Struct1T.Shape<LeafNode<*>> {
  companion object {
    val T: DataType<Update> =
      struct("Update") {
        it.field("leaf_node", LeafNode.dataT)
      }.lift(::Update)
  }
}

data class Remove(
  val removed: LeafIndex,
) : Proposal(ProposalType.Remove), Struct1T.Shape<LeafIndex> {
  override val mayBeExternal: Boolean = true

  companion object {
    val T: DataType<Remove> =
      struct("Remove") {
        it.field("removed", LeafIndex.dataT)
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
        it.field("psk", PreSharedKeyId.dataT)
      }.lift(::PreSharedKey)
  }
}

data class ReInit(
  val groupId: GroupId,
  val protocolVersion: ProtocolVersion,
  val cipherSuite: CipherSuite,
  val extensions: List<GroupContextExtension<*>>,
) : Proposal(ProposalType.ReInit),
  Struct4T.Shape<GroupId, ProtocolVersion, CipherSuite, List<GroupContextExtension<*>>> {
  override val mayBeExternal: Boolean = true
  override val requiresPath: Boolean = false

  companion object {
    val T: DataType<ReInit> =
      struct("ReInit") {
        it.field("group_id", GroupId.dataT)
          .field("version", ProtocolVersion.T)
          .field("cipher_suite", CipherSuite.T)
          .field("extensions", GroupContextExtension.dataT.extensionList())
      }.lift(::ReInit)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as ReInit

    if (groupId neq other.groupId) return false
    if (protocolVersion != other.protocolVersion) return false
    if (cipherSuite != other.cipherSuite) return false
    if (extensions != other.extensions) return false
    if (mayBeExternal != other.mayBeExternal) return false
    if (requiresPath != other.requiresPath) return false

    return true
  }

  override fun hashCode(): Int {
    var result = groupId.hashCode
    result = 31 * result + protocolVersion.hashCode()
    result = 31 * result + cipherSuite.hashCode()
    result = 31 * result + extensions.hashCode()
    result = 31 * result + mayBeExternal.hashCode()
    result = 31 * result + requiresPath.hashCode()
    return result
  }
}

data class ExternalInit(
  val kemOutput: KemOutput,
) : Proposal(ProposalType.ExternalInit), Struct1T.Shape<KemOutput> {
  companion object {
    val T: DataType<ExternalInit> =
      struct("ExternalInit") {
        it.field("kem_output", KemOutput.dataT)
      }.lift(::ExternalInit)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as ExternalInit

    return kemOutput eq other.kemOutput
  }

  override fun hashCode(): Int {
    return kemOutput.hashCode
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
        it.field("extensions", GroupContextExtension.dataT.extensionList())
      }.lift(::GroupContextExtensions)
  }
}
