package com.github.traderjoe95.mls.codec.type.struct

import com.github.traderjoe95.mls.codec.Struct
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.struct.member.Field
import com.github.traderjoe95.mls.codec.type.struct.member.Member

sealed class StructT<S : Struct?>(
  override val name: String,
  val members: List<Member<*>>,
) : DataType<S> {
  constructor(name: String, vararg members: Member<*>) : this(name, members.toList())

  final override val encodedLength: UInt? =
    members.map { it.encodedLength }.fold(0U as UInt?) { result, fieldLength ->
      result?.let { r ->
        fieldLength?.let { r + it }
      }
    }

  operator fun get(fieldName: String): Field<*>? = members.filterIsInstance<Field<*>>().find { it.name == fieldName }

  override fun toString(): String = "struct {\n  ${members.joinToString(";\n  ", postfix = ";")}\n} $name"

  data class Lifted<S : Struct, V>(
    val structT: StructT<S>,
    val up: (S) -> V,
    val down: (V) -> S,
  ) : DataType<V> by structT.derive({ up(it) }, { down(it) })
}
