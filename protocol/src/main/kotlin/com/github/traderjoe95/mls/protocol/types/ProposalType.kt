package com.github.traderjoe95.mls.protocol.types

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError
import kotlin.random.Random

enum class ProposalType(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<ProposalType> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0x0000U, false),

  Add(0x0001U),
  Update(0x0002U),
  Remove(0x0003U),
  Psk(0x0004U),
  ReInit(0x0005U),
  ExternalInit(0x0006U),
  GroupContextExtensions(0x0007U),

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

  override fun toString(): String = "$name[$asUShort]"

  companion object {
    val T: EnumT<ProposalType> = throwAnyError { enum(upperBound = 0xFFFFU) }

    operator fun invoke(type: UShort): ProposalType? = entries.find { it.isValid && type in it.ord }

    fun grease(individualProbability: Double = 0.1): List<UShort> =
      entries
        .filter { it.name.startsWith("GREASE") && Random.nextDouble() < individualProbability }
        .map { it.asUShort }

    val EXTERNAL_SENDER: Set<ProposalType> = setOf(Add, Remove, Psk, ReInit, GroupContextExtensions)
    val EXTERNAL_COMMIT: Set<ProposalType> = setOf(Remove, Psk, ExternalInit)
    val ORDER: List<ProposalType> =
      listOf(
        GroupContextExtensions,
        Update,
        Remove,
        Add,
        Psk,
        ExternalInit,
        ReInit,
      )
  }
}
