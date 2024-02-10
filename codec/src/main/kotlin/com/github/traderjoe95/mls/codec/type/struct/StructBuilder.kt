package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.None
import arrow.core.Option
import arrow.core.nonEmptyListOf
import arrow.core.raise.Raise
import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct
import com.github.traderjoe95.mls.codec.error.SelectError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.struct.member.Field
import com.github.traderjoe95.mls.codec.type.struct.member.Field.Companion.ofType
import com.github.traderjoe95.mls.codec.type.struct.member.Select
import com.github.traderjoe95.mls.codec.type.struct.member.SelectBuilder

abstract class StructBuilder<S : Struct?, T : StructT<S>> : StructBuilderMixin<T>() {
  interface Initial {
    fun <A> field(
      fieldName: String,
      type: DataType<A>,
    ): Struct1T.Builder<A>

    fun <A> field(
      fieldName: String,
      type: DataType<A>,
      constant: A,
    ): Struct1T.Builder<A>
  }

  @PublishedApi
  internal class InitialImpl(override val name: String) : Initial, StructBuilderMixin<Struct0T>() {
    override val nextIndex: UInt = 0U

    override fun <A> field(
      fieldName: String,
      type: DataType<A>,
    ): Struct1T.Builder<A> = Struct1T.Builder(name, createField(fieldName, type))

    override fun <A> field(
      fieldName: String,
      type: DataType<A>,
      constant: A,
    ): Struct1T.Builder<A> = Struct1T.Builder(name, createField(fieldName, type, constant.some()))

    override fun buildStructT(): Struct0T = Struct0T
  }
}

sealed class StructBuilderMixin<T : StructT<*>> {
  @PublishedApi
  internal abstract val name: String

  @PublishedApi
  internal abstract val nextIndex: UInt

  protected fun <_T> createField(
    fieldName: String,
    type: DataType<_T>,
    constant: Option<_T> = None,
  ): Field<_T> = fieldName.ofType(type, nextIndex, constant)

  context(Raise<SelectError>)
  @PublishedApi
  internal inline fun <_T, reified _E> createSelect(
    enumT: EnumT<_E>,
    fieldName: String,
    vararg nestedPath: String,
    block: SelectBuilder<_T, _E>.() -> SelectBuilder<_T, _E>,
  ): Select<_T, _E> where _E : ProtocolEnum<_E> =
    SelectBuilder<_T, _>(
      nonEmptyListOf(fieldName, *nestedPath),
      enumT,
      nextIndex,
    ).block().build(buildStructT())

  @PublishedApi
  internal abstract fun buildStructT(): T
}
