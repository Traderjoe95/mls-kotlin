package com.github.traderjoe95.mls.protocol.types

import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import org.bouncycastle.cert.X509CertificateHolder
import kotlin.random.Random

enum class CredentialType(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<CredentialType> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0x0000U, false),

  Basic(0x0001U),
  X509(0x0002U),

  // GREASE
  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_1(0x0A0AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_2(0x1A1AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_3(0x2A2AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_4(0x3A3AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_5(0x4A4AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_6(0x5A5AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_7(0x6A6AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_8(0x7A7AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_9(0x8A8AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_10(0x9A9AU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_11(0xAAAAU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_12(0xBABAU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_13(0xCACAU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_14(0xDADAU, false),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  GREASE_15(0xEAEAU, false),
  ;

  override val ord: UIntRange = ord..ord
  val asUShort: UShort = ord.toUShort()

  override fun toString(): String = "$name($asUShort)"

  companion object {
    val T: EnumT<CredentialType> = throwAnyError { enum(upperBound = 0xFFFFU) }

    operator fun invoke(type: UShort): CredentialType? = entries.find { it.isValid && type in it.ord }

    fun grease(individualProbability: Double = 0.1): List<UShort> =
      entries
        .filter { it.name.startsWith("GREASE") && Random.nextDouble() < individualProbability }
        .map { it.asUShort }
  }
}

sealed class Credential(
  val credentialType: CredentialType,
) : Struct2T.Shape<CredentialType, Credential> {
  override fun component1(): CredentialType = credentialType

  override fun component2(): Credential = this

  companion object {
    val T: DataType<Credential> by lazy {
      throwAnyError {
        struct("Credential") {
          it.field("credential_type", CredentialType.T)
            .select<Credential, _>(CredentialType.T, "credential_type") {
              case(CredentialType.Basic).then(BasicCredential.T, "identity")
                .case(CredentialType.X509).then(X509Credential.T, "certificates")
            }
        }.lift { _, cred -> cred }
      }
    }
  }
}

val Certificate: DataType<X509CertificateHolder> =
  struct("Certificate") {
    it.field("cert_data", opaque[V])
  }.derive(
    {
      try {
        X509CertificateHolder(it.field1)
      } catch (e: Exception) {
        raise(DecoderError.UnexpectedError("Invalid certificate: $e"))
      }
    },
    { Struct1(it.encoded) },
  )

class BasicCredential(val identity: ByteArray) : Credential(CredentialType.Basic) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as BasicCredential

    return identity.contentEquals(other.identity)
  }

  override fun hashCode(): Int {
    return identity.contentHashCode()
  }

  companion object {
    val T: DataType<BasicCredential> = opaque[V].derive({ BasicCredential(it) }, { it.identity })
  }
}

class X509Credential(
  val certificates: List<X509CertificateHolder>,
) : Credential(CredentialType.X509) {
  companion object {
    val T: DataType<X509Credential> = Certificate[V].derive({ X509Credential(it) }, { it.certificates })
  }
}
