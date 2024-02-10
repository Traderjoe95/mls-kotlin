package com.github.traderjoe95.mls.codec.type.struct.member

import arrow.core.None
import arrow.core.Option
import arrow.core.Some
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Struct
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct0T
import com.github.traderjoe95.mls.codec.type.struct.StructT
import com.github.traderjoe95.mls.codec.util.Slice
import kotlin.reflect.KClass

class Field<V>
  @PublishedApi
  internal constructor(
    val name: String?,
    val type: DataType<V>,
    override val index: UInt,
    val constant: Option<V> = None,
    internal val checkedType: KClass<out V & Any>? = null,
  ) : Member<V>() {
    override val encodedLength: UInt?
      get() = type.encodedLength

    context(Raise<EncoderError>)
    override fun encodeValue(
      value: V,
      struct: Struct,
      structT: StructT<*>,
    ): ByteArray {
      if (checkedType?.isInstance(value) == false) {
        raise(EncoderError.WrongVariant(structT.name, index, type.name, value))
      } else if (type == Struct0T && value != null) {
        raise(EncoderError.WrongVariant(structT.name, index, "null (= struct {})", value))
      }

      return when (constant) {
        is None -> type.encode(value)
        is Some ->
          if (value != constant.value) {
            raise(EncoderError.InvalidFieldValue(structT.name, index, constant.value, value))
          } else {
            type.encode(value)
          }
      }
    }

    context(Raise<DecoderError>)
    override fun decodeValue(
      bytes: Slice,
      alreadyDecoded: Struct?,
      structT: StructT<*>,
    ): Pair<V, Slice> =
      type.decode(bytes).also { (value, _) ->
        if (constant is Some && value != constant.value) {
          raise(DecoderError.InvalidFieldValue(bytes.firstIndex, structT.name, index, constant.value, value))
        }
      }

    override fun toString(): String = "${type.name} $name"

    companion object {
      internal fun <V> String.ofType(
        type: DataType<V>,
        index: UInt,
        constant: Option<V> = None,
        checkedType: KClass<out V & Any>? = null,
      ): Field<V> = Field(this, type, index, constant, checkedType)
    }
  }
