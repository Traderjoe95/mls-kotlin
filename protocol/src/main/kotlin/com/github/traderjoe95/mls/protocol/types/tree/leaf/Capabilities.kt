package com.github.traderjoe95.mls.protocol.types.tree.leaf

import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.CredentialType
import com.github.traderjoe95.mls.protocol.types.ExtensionType
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion

data class Capabilities(
  val versions: List<ProtocolVersion>,
  val cipherSuites: List<UShort>,
  val extensions: List<UShort>,
  val proposals: List<UShort>,
  val credentials: List<UShort>,
) :
  Struct5T.Shape<List<ProtocolVersion>, List<UShort>, List<UShort>, List<UShort>, List<UShort>> {
  operator fun contains(protocolVersion: ProtocolVersion): Boolean = protocolVersion in versions

  operator fun contains(cipherSuite: CipherSuite): Boolean = cipherSuite.asUShort in cipherSuites

  operator fun contains(extensionType: ExtensionType): Boolean =
    extensionType.asUShort in extensions || extensionType.asUShort in DEFAULT_EXTENSIONS

  @JvmName("containsExtensionTypes")
  operator fun contains(extensionTypes: Iterable<ExtensionType>): Boolean = extensionTypes.all { it in this }

  infix fun supportsExtension(extensionType: UShort): Boolean = extensionType in extensions || extensionType in DEFAULT_EXTENSIONS

  operator fun contains(proposalType: ProposalType): Boolean =
    proposalType.asUShort in proposals || proposalType.asUShort in DEFAULT_PROPOSALS

  @JvmName("containsProposalTypes")
  operator fun contains(proposalTypes: Iterable<ProposalType>): Boolean = proposalTypes.all { it in this }

  operator fun contains(credentialType: CredentialType): Boolean = credentialType.asUShort in credentials

  @JvmName("containsCredentialTypes")
  operator fun contains(credentialTypes: Iterable<CredentialType>): Boolean = credentialTypes.all { it in this }

  override fun toString(): String =
    "Capabilities(versions=$versions, " +
      "cipherSuites=${cipherSuites.map { CipherSuite(it) ?: it }}, " +
      "extensions=${extensions.map { ExtensionType(it) ?: it }}, " +
      "proposals=${proposals.map { ProposalType(it) ?: it }}, " +
      "credentials=${credentials.map { CredentialType(it) ?: it }}"

  companion object {
    val T: DataType<Capabilities> =
      struct("Capabilities") {
        it.field("versions", ProtocolVersion.T[V])
          .field("cipher_suites", uint16.asUShort[V])
          .field("extensions", uint16.asUShort[V])
          .field("proposals", uint16.asUShort[V])
          .field("credentials", uint16.asUShort[V])
      }.lift(::Capabilities)

    fun create(
      credentials: List<CredentialType>,
      cipherSuites: List<CipherSuite>? = null,
    ): Capabilities =
      Capabilities(
        listOf(ProtocolVersion.MLS_1_0),
        (cipherSuites?.map { it.asUShort } ?: CipherSuite.VALID) + CipherSuite.grease(),
        ProposalType.grease(),
        ExtensionType.grease(),
        credentials.map { it.asUShort } + CredentialType.grease(),
      )

    private val DEFAULT_PROPOSALS: Set<UShort> =
      setOf(
        ProposalType.Add.asUShort,
        ProposalType.Update.asUShort,
        ProposalType.Remove.asUShort,
        ProposalType.Psk.asUShort,
        ProposalType.ReInit.asUShort,
        ProposalType.ExternalInit.asUShort,
        ProposalType.GroupContextExtensions.asUShort,
      )

    private val DEFAULT_EXTENSIONS: Set<UShort> =
      setOf(
        ExtensionType.ApplicationId.asUShort,
        ExtensionType.RatchetTree.asUShort,
        ExtensionType.RequiredCapabilities.asUShort,
        ExtensionType.ExternalPub.asUShort,
        ExtensionType.ExternalSenders.asUShort,
      )
  }
}
