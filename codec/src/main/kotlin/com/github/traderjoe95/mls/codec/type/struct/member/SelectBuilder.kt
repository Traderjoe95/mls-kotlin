package com.github.traderjoe95.mls.codec.type.struct.member

import arrow.core.Nel
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.SelectError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.struct.Struct0T
import com.github.traderjoe95.mls.codec.type.struct.StructT
import kotlin.experimental.ExperimentalTypeInference

@Suppress("UNCHECKED_CAST")
@JvmName("orElseNonNull")
inline fun <V : Any, reified VV : V, E> SelectBuilder<V, E>.orElse(
  dataType: DataType<VV>,
  label: String? = null,
): SelectBuilder<V, E> where E : ProtocolEnum<E> = orElse(Field(label, dataType as DataType<V>, index, checkedType = VV::class))

@Suppress("UNCHECKED_CAST")
@JvmName("orElseNullable")
inline fun <V : Any, reified VV : V, E> SelectBuilder<V?, E>.orElse(
  dataType: DataType<VV>,
  label: String? = null,
): SelectBuilder<V?, E> where E : ProtocolEnum<E> = orElse(Field(label, dataType as DataType<V?>, index, checkedType = VV::class))

@Suppress("UNCHECKED_CAST")
@JvmName("orElseNothingNullable")
fun <V : Any, E> SelectBuilder<V?, E>.orElseNothing(): SelectBuilder<V?, E> where E : ProtocolEnum<E> =
  orElse(Field(null, Struct0T, index) as Field<V?>)

@Suppress("UNCHECKED_CAST")
@JvmName("thenNonNull")
inline fun <V : Any, reified VV : V, E> SelectBuilder.Case<V, E>.then(
  dataType: DataType<VV>,
  label: String? = null,
): SelectBuilder<V, E> where E : ProtocolEnum<E> = thenField(Field(label, dataType as DataType<V>, parent.index, checkedType = VV::class))

@OptIn(ExperimentalTypeInference::class)
@Suppress("UNCHECKED_CAST")
@JvmName("thenNullable")
@BuilderInference
inline fun <V : Any, reified VV : V, E> SelectBuilder.Case<V?, E>.then(
  dataType: DataType<VV>,
  label: String? = null,
): SelectBuilder<V?, E> where E : ProtocolEnum<E> = thenField(Field(label, dataType as DataType<V?>, parent.index, checkedType = VV::class))

@Suppress("UNCHECKED_CAST")
@JvmName("thenNothingNullable")
fun <V : Any, E> SelectBuilder.Case<V?, E>.thenNothing(): SelectBuilder<V?, E> where E : ProtocolEnum<E> =
  thenField(Field(null, Struct0T, parent.index) as Field<V?>)

class SelectBuilder<V, E>(
  @PublishedApi internal val condition: Nel<String>,
  @PublishedApi internal val conditionType: EnumT<E>,
  @PublishedApi internal val index: UInt,
  @PublishedApi internal val cases: MutableMap<E, Field<V>> = mutableMapOf(),
) where E : ProtocolEnum<E> {
  fun case(
    firstValue: E,
    vararg moreValues: E,
  ): Case<V, E> = Case(this, setOf(firstValue, *moreValues))

  @PublishedApi internal fun orElse(field: Field<V>): SelectBuilder<V, E> =
    apply {
      (conditionType.values.toSet() - cases.keys).filter { it.isValid }.forEach { cases[it] = field }
    }

  context(Raise<SelectError>)
  @PublishedApi
  internal fun build(structT: StructT<*>): Select<V, E> =
    Select(condition, conditionType, cases.toMap().filterKeys { it.isValid }, index, structT)

  class Case<V, E> internal constructor(
    @PublishedApi internal val parent: SelectBuilder<V, E>,
    @PublishedApi internal val values: Set<E>,
  ) where E : ProtocolEnum<E> {
    fun or(value: E): Case<V, E> = Case(parent, values + value)

    @PublishedApi internal fun thenField(field: Field<V>): SelectBuilder<V, E> =
      parent.apply {
        values.forEach { cases[it] = field }
      }
  }
}
