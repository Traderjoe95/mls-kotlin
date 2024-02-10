package com.github.traderjoe95.mls.codec.type

import arrow.core.None
import arrow.core.Option
import arrow.core.Some
import arrow.core.raise.Raise
import arrow.core.some
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.member.thenNothing
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError

val optional: OptionalT.Companion = OptionalT.Companion

class OptionalT<V : Any>
  @PublishedApi
  internal constructor(
    val valueType: DataType<V>,
    struct: DataType<ProtocolOption<V>>,
  ) : DataType.Derived<Option<V>, OptionalT.ProtocolOption<V>>(struct) {
    context(Raise<DecoderError>)
    override fun convertUp(value: ProtocolOption<V>): Option<V> = value.asOption

    context(Raise<EncoderError>)
    override fun convertDown(value: Option<V>): ProtocolOption<V> = ProtocolOption(value)

    companion object {
      inline operator fun <reified V : Any> get(dataType: DataType<V>): DataType<Option<V>> = OptionalT(dataType, structT(dataType))

      @PublishedApi internal inline fun <reified V : Any> structT(valueType: DataType<V>): DataType<ProtocolOption<V>> =
        struct("optional<${valueType.name}>") { struct ->
          struct.field("present", Presence.T)
            .select<V?, _>(Presence.T, "present") {
              case(Presence.PRESENT).then(valueType, "value")
                .case(Presence.ABSENT).thenNothing()
            }
        }.lift(ProtocolOption.Companion::invoke)
    }

    enum class Presence(ord: UInt) : ProtocolEnum<Presence> {
      ABSENT(0U),
      PRESENT(1U),
      ;

      override val ord: UIntRange = ord..ord
      override val isValid: Boolean = true

      companion object {
        val T: EnumT<Presence> = throwAnyError { enum() }
      }
    }

    sealed interface ProtocolOption<out V : Any> : Struct2T.Shape<Presence, V?> {
      val asOption: Option<V>

      companion object {
        internal operator fun <V : Any> invoke(option: Option<V>): ProtocolOption<V> =
          when (option) {
            is None -> Absent
            is Some -> Present(option.value)
          }

        @PublishedApi internal operator fun <V : Any> invoke(
          presence: Presence,
          v: V?,
        ): ProtocolOption<V> =
          if (presence == Presence.ABSENT || v == null) {
            Absent
          } else {
            Present(v)
          }
      }

      data object Absent : ProtocolOption<Nothing> {
        override val asOption: Option<Nothing>
          get() = None

        override fun component1(): Presence = Presence.ABSENT

        override fun component2(): Nothing? = null
      }

      class Present<out V : Any> internal constructor(val value: V) : ProtocolOption<V> {
        override val asOption: Option<V>
          get() = value.some()

        override fun component1(): Presence = Presence.PRESENT

        override fun component2(): V = value
      }
    }
  }
