package com.github.traderjoe95.mls.codec.type.struct.member

import arrow.core.Nel
import arrow.core.raise.Raise
import arrow.core.toNonEmptyListOrNull
import com.github.traderjoe95.mls.codec.Struct
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.SelectError
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.struct.StructT
import com.github.traderjoe95.mls.codec.util.Slice

context(Raise<SelectError>)
class Select<V, E> internal constructor(
  val condition: Nel<String>,
  val conditionType: EnumT<E>,
  @PublishedApi internal val cases: Map<E, Field<V>>,
  override val index: UInt,
  private val refStructT: StructT<*>,
) : Member<V>() where E : ProtocolEnum<E> {
  init {
    check()
  }

  override val encodedLength: UInt? by lazy {
    cases.values.map { it.encodedLength }.toSet().let { sizes ->
      sizes.firstOrNull()?.takeIf { sizes.size == 1 }
    }
  }

  context(Raise<SelectError>)
  @PublishedApi
  internal fun check() {
    // Check that all required branches are handled
    (conditionType.values.filter(ProtocolEnum<*>::isValid).toSet() - cases.keys).let {
      if (it.isNotEmpty()) {
        raise(
          SelectError.UnhandledSelectBranches(
            refStructT.name,
            conditionType.name,
            it.map(ProtocolEnum<*>::name).toSet(),
          ),
        )
      }
    }

    // Check that the condition field exists and is of the required type
    condition.checkCondition(refStructT, conditionType)
  }

  private fun extractValue(
    struct: Struct,
    structT: StructT<*>,
  ): E = condition.extractValue(struct, structT)

  context(Raise<EncoderError>)
  override fun encodeValue(
    value: V,
    struct: Struct,
    structT: StructT<*>,
  ): ByteArray =
    extractValue(struct, structT).let {
      cases[it] ?: error("Unreachable state")
    }.encodeValue(value, struct, structT)

  context(Raise<DecoderError>)
  override fun decodeValue(
    bytes: Slice,
    alreadyDecoded: Struct?,
    structT: StructT<*>,
  ): Pair<V, Slice> =
    // This non-null cast is safe, as a select can never be the first member; this is prevented by API
    extractValue(alreadyDecoded!!, structT).let {
      // We know the case exists, because we checked that all valid enum branches are covered when the Select was built
      cases[it] ?: error("Unreachable state")
    }.decodeValue(bytes, alreadyDecoded, structT)

  override fun toString(): String =
    "select(${refStructT.name}.${condition.joinToString(".")}) {\n    ${
      cases.entries.sortedBy { it.key }.joinToString(";\n    ", postfix = ";") { (case, field) ->
        "case ${conditionType.name}.$case: ${field.type.name}${field.name?.let { " $it" } ?: ""}"
      }
    }\n  }"

  companion object {
    context(Raise<SelectError>)
    private fun Nel<String>.checkCondition(
      structT: StructT<*>,
      expectedType: EnumT<*>,
    ) {
      structT[head]?.let { field ->
        tail.toNonEmptyListOrNull()?.let { tailNel ->
          when (field.type) {
            is StructT<*> -> tailNel.checkCondition(field.type, expectedType)
            is StructT.Lifted<*, *> -> tailNel.checkCondition(field.type.structT, expectedType)
            else -> raise(SelectError.ExpectedStruct(structT.name, head, field.type.name))
          }
        }
          ?: field.type.takeIf { it == expectedType }
          ?: raise(SelectError.ExpectedEnum(structT.name, field.name!!, expectedType.name, field.type.name))
      } ?: raise(SelectError.UnknownField(structT.name, head))
    }

    @Suppress("UNCHECKED_CAST")
    private fun <E> Nel<String>.extractValue(
      struct: Struct,
      structT: StructT<*>,
    ): E
      where E : ProtocolEnum<E> =
      // We know this field exists and that the select is well-formed on the given struct type and struct,
      // otherwise there is a failure either in check(...) or in the previous Field decoder(s)
      structT[head]?.let { field ->
        val fieldValue = struct[field.index]

        tail.toNonEmptyListOrNull()
          ?.let {
            if (field.type is StructT.Lifted<*, *>) {
              it.extractValue((field.type as StructT.Lifted<*, Any?>).down(fieldValue), field.type.structT)
            } else {
              it.extractValue(fieldValue as Struct, field.type as StructT<*>)
            }
          }
          ?: fieldValue as E
      } ?: error("Unknown field $head in $structT")
  }
}
