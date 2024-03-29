package com.github.traderjoe95.mls.protocol.types

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint16
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import kotlin.random.Random

enum class ExtensionType(
  ord: UInt,
  override val isValid: Boolean = true,
) : ProtocolEnum<ExtensionType> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0x0000U, isValid = false),

  ApplicationId(0x0001U),
  RatchetTree(0x0002U),
  RequiredCapabilities(0x0003U),
  ExternalPub(0x0004U),
  ExternalSenders(0x0005U),

  // GREASE
  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_1(0x0A0AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_2(0x1A1AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_3(0x2A2AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_4(0x3A3AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_5(0x4A4AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_6(0x5A5AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_7(0x6A6AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_8(0x7A7AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_9(0x8A8AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_10(0x9A9AU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_11(0xAAAAU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_12(0xBABAU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_13(0xCACAU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_14(0xDADAU, isValid = false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_15(0xEAEAU, isValid = false),
  ;

  override val ord: UIntRange = ord..ord
  val asUShort: UShort = ord.toUShort()

  override fun toString(): String = "$name($asUShort)"

  companion object {
    val T: EnumT<ExtensionType> = throwAnyError { enum(upperBound = 0xFFFFU) }

    operator fun invoke(type: UShort): ExtensionType? = entries.find { it.isValid && type in it.ord }

    fun grease(individualProbability: Double = 0.1): List<UShort> =
      entries
        .filter { it.name.startsWith("GREASE") && Random.nextDouble() < individualProbability }
        .map { it.asUShort }
  }
}

sealed interface Extension<V : Extension<V>> {
  val type: UShort
  val valueT: DataType<V>

  val extensionType: ExtensionType?
    get() = ExtensionType(type)

  companion object {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming", "UNCHECKED_CAST")
    val T: DataType<Extension<*>> =
      struct("Extension") {
        it.field("extension_type", uint16.asUShort)
          .field("extension_data", opaque[V])
      }.derive(
        { (type, extensionValue) -> decodeExtension(type, extensionValue) },
        { Struct2(it.type, (it.valueT as DataType<Extension<*>>).encode(it)) },
      )

    fun Raise<DecoderError>.decodeExtension(
      type: UShort,
      value: ByteArray,
    ): Extension<*> =
      when (type) {
        in ExtensionType.ApplicationId.ord ->
          value.decodeAs(ApplicationId.T)

        in ExtensionType.RatchetTree.ord ->
          value.decodeAs(RatchetTree.T)

        in ExtensionType.RequiredCapabilities.ord ->
          value.decodeAs(RequiredCapabilities.T)

        in ExtensionType.ExternalPub.ord ->
          value.decodeAs(ExternalPub.T)

        in ExtensionType.ExternalSenders.ord ->
          value.decodeAs(ExternalSenders.T)

        else -> UnknownExtension(type, value)
      }

    fun grease(
      individualProbability: Double = 0.1,
      maxValueSize: UInt = 255U,
    ): Array<UnknownExtension> =
      ExtensionType.grease(individualProbability)
        .map { UnknownExtension(it, Random.nextBytes(maxValueSize.toInt())) }
        .toTypedArray()
  }
}

abstract class HasExtensions<V : Extension<*>> {
  abstract val extensions: List<V>

  inline fun <reified T : V> extension(): T? = extensions.filterIsInstance<T>().firstOrNull()

  inline fun <reified T : V> hasExtension(): Boolean = extensions.filterIsInstance<T>().isNotEmpty()
}

inline fun <reified E : Extension<*>> DataType<Extension<*>>.asSubtype(): DataType<E> =
  derive(
    up = { ext ->
      if (ext is E) {
        ext
      } else {
        raise(
          DecoderError.UnexpectedError(
            "Unsupported extension ${ext::class.simpleName} in context of ${E::class.simpleName}",
          ),
        )
      }
    },
    down = { it },
    name = E::class.simpleName,
  )

fun <E : Extension<*>> DataType<E>.extensionList(): DataType<List<E>> =
  this[V].derive(
    up = { extensions ->
      extensions
        .groupBy { it.type }
        .filter { it.value.size > 1 }
        .takeIf { it.isNotEmpty() }
        ?.keys
        ?.let { duplicates ->
          raise(DecoderError.UnexpectedError("Duplicate extensions: ${duplicates.map { ExtensionType(it) ?: it }}"))
        }

      extensions
    },
    down = { it },
  )

sealed interface GroupContextExtension<V : GroupContextExtension<V>> : Extension<V> {
  companion object : Encodable<GroupContextExtension<*>> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<GroupContextExtension<*>> = Extension.T.asSubtype<GroupContextExtension<*>>()
  }
}

typealias GroupContextExtensions = List<GroupContextExtension<*>>

sealed interface GroupInfoExtension<V : GroupInfoExtension<V>> : Extension<V> {
  companion object : Encodable<GroupInfoExtension<*>> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<GroupInfoExtension<*>> = Extension.T.asSubtype<GroupInfoExtension<*>>()
  }
}

typealias GroupInfoExtensions = List<GroupInfoExtension<*>>

sealed interface KeyPackageExtension<V : KeyPackageExtension<V>> : Extension<V> {
  companion object : Encodable<KeyPackageExtension<*>> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<KeyPackageExtension<*>> = Extension.T.asSubtype<KeyPackageExtension<*>>()
  }
}

typealias KeyPackageExtensions = List<KeyPackageExtension<*>>

sealed interface LeafNodeExtension<V : LeafNodeExtension<V>> : Extension<V> {
  companion object : Encodable<LeafNodeExtension<*>> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<LeafNodeExtension<*>> = Extension.T.asSubtype<LeafNodeExtension<*>>()
  }
}

typealias LeafNodeExtensions = List<LeafNodeExtension<*>>

data class ApplicationId(
  override val bytes: ByteArray,
) : LeafNodeExtension<ApplicationId>, RefinedBytes<ApplicationId> {
  override val type: UShort
    get() = ExtensionType.ApplicationId.asUShort
  override val valueT: DataType<ApplicationId>
    get() = T

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as ApplicationId

    return bytes.contentEquals(other.bytes)
  }

  override fun hashCode(): Int {
    return bytes.contentHashCode()
  }

  companion object {
    val T: DataType<ApplicationId> = RefinedBytes.dataT(::ApplicationId, "ApplicationId")
  }
}

data class RequiredCapabilities(
  val extensionTypes: List<ExtensionType> = listOf(),
  val proposalTypes: List<ProposalType> = listOf(),
  val credentialTypes: List<CredentialType> = listOf(),
) : GroupContextExtension<RequiredCapabilities>,
  Struct3T.Shape<List<ExtensionType>, List<ProposalType>, List<CredentialType>> {
  override val type: UShort = ExtensionType.RequiredCapabilities.asUShort
  override val valueT: DataType<RequiredCapabilities> = T

  fun isCompatible(capabilities: Capabilities): Boolean =
    extensionTypes in capabilities && proposalTypes in capabilities && credentialTypes in capabilities

  companion object {
    val T: DataType<RequiredCapabilities> =
      struct("RequiredCapabilities") {
        it.field("extension_types", ExtensionType.T[V])
          .field("proposal_types", ProposalType.T[V])
          .field("credential_types", CredentialType.T[V])
      }.lift(::RequiredCapabilities)
  }
}

data class ExternalSenders(
  val externalSenders: List<ExternalSender>,
) : GroupContextExtension<ExternalSenders> {
  override val type: UShort = ExtensionType.ExternalSenders.asUShort
  override val valueT: DataType<ExternalSenders> = T

  constructor(externalSender: ExternalSender) : this(listOf(externalSender))

  operator fun plus(externalSender: ExternalSender): ExternalSenders = ExternalSenders(externalSenders + externalSender)

  companion object {
    val T: DataType<ExternalSenders> =
      ExternalSender.T[V].derive(
        { ExternalSenders(it) },
        { it.externalSenders },
        "ExternalSenders",
      )
  }

  data class ExternalSender(
    val signaturePublicKey: SignaturePublicKey,
    val credential: Credential,
  ) : Struct2T.Shape<SignaturePublicKey, Credential> {
    companion object {
      val T: DataType<ExternalSender> =
        struct("ExternalSender") {
          it.field("signature_key", SignaturePublicKey.T)
            .field("credential", Credential.T)
        }.lift(::ExternalSender)
    }
  }
}

data class RatchetTree(
  val tree: PublicRatchetTree,
) : GroupInfoExtension<RatchetTree> {
  constructor(tree: com.github.traderjoe95.mls.protocol.tree.RatchetTree) : this(tree.public)

  override val type: UShort = ExtensionType.RatchetTree.asUShort
  override val valueT: DataType<RatchetTree> = T

  companion object {
    val T: DataType<RatchetTree> = PublicRatchetTree.T.derive({ RatchetTree(it) }, { it.tree })
  }
}

data class ExternalPub(
  val externalPub: HpkePublicKey,
) : GroupInfoExtension<ExternalPub>, Struct1T.Shape<HpkePublicKey> {
  override val type: UShort = ExtensionType.ExternalPub.asUShort
  override val valueT: DataType<ExternalPub> = T

  companion object {
    val T: DataType<ExternalPub> =
      struct("ExternalPub") {
        it.field("external_pub", HpkePublicKey.T)
      }.lift(::ExternalPub)
  }
}

data class UnknownExtension(
  override val type: UShort,
  val value: ByteArray,
) : LeafNodeExtension<UnknownExtension>,
  KeyPackageExtension<UnknownExtension>,
  GroupInfoExtension<UnknownExtension> {
  override val valueT: DataType<UnknownExtension> =
    object : DataType<UnknownExtension> {
      override val name: String = "Unknown Extension"

      context(Raise<EncoderError>)
      override fun encode(value: UnknownExtension): ByteArray = value.value

      context(Raise<DecoderError>)
      override fun decode(bytes: Slice): Pair<UnknownExtension, Slice> = raise(DecoderError.UnexpectedError("Decoding not supported"))
    }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as UnknownExtension

    if (type != other.type) return false
    if (!value.contentEquals(other.value)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = type.hashCode()
    result = 31 * result + value.contentHashCode()
    return result
  }
}
