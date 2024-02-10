package com.github.traderjoe95.mls.codec

import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.Struct6T
import com.github.traderjoe95.mls.codec.type.struct.Struct7T
import com.github.traderjoe95.mls.codec.type.struct.Struct8T
import com.github.traderjoe95.mls.codec.type.struct.Struct9T

sealed class Struct(val fields: List<*>) {
  constructor(vararg fields: Any?) : this(fields.toList())

  val size: UInt
    get() = fields.size.toUInt()

  operator fun get(index: UInt): Any? = fields[index.toInt()]
}

typealias Struct0 = Nothing

data class Struct1<out A>(val field1: A) : Struct(field1), Struct1T.Shape<A>

data class Struct2<out A, out B>(val field1: A, val field2: B) : Struct(field1, field2), Struct2T.Shape<A, B>

data class Struct3<out A, out B, out C>(
  val field1: A,
  val field2: B,
  val field3: C,
) : Struct(field1, field2, field3), Struct3T.Shape<A, B, C>

data class Struct4<out A, out B, out C, out D>(
  val field1: A,
  val field2: B,
  val field3: C,
  val field4: D,
) : Struct(field1, field2, field3, field4), Struct4T.Shape<A, B, C, D>

data class Struct5<out A, out B, out C, out D, out E>(
  val field1: A,
  val field2: B,
  val field3: C,
  val field4: D,
  val field5: E,
) : Struct(field1, field2, field3, field4, field5), Struct5T.Shape<A, B, C, D, E>

data class Struct6<out A, out B, out C, out D, out E, out F>(
  val field1: A,
  val field2: B,
  val field3: C,
  val field4: D,
  val field5: E,
  val field6: F,
) : Struct(field1, field2, field3, field4, field5, field6), Struct6T.Shape<A, B, C, D, E, F>

data class Struct7<out A, out B, out C, out D, out E, out F, out G>(
  val field1: A,
  val field2: B,
  val field3: C,
  val field4: D,
  val field5: E,
  val field6: F,
  val field7: G,
) : Struct(field1, field2, field3, field4, field5, field6, field7), Struct7T.Shape<A, B, C, D, E, F, G>

data class Struct8<out A, out B, out C, out D, out E, out F, out G, out H>(
  val field1: A,
  val field2: B,
  val field3: C,
  val field4: D,
  val field5: E,
  val field6: F,
  val field7: G,
  val field8: H,
) : Struct(field1, field2, field3, field4, field5, field6, field7, field8), Struct8T.Shape<A, B, C, D, E, F, G, H>

data class Struct9<out A, out B, out C, out D, out E, out F, out G, out H, out I>(
  val field1: A,
  val field2: B,
  val field3: C,
  val field4: D,
  val field5: E,
  val field6: F,
  val field7: G,
  val field8: H,
  val field9: I,
) : Struct(field1, field2, field3, field4, field5, field6, field7, field8, field9),
  Struct9T.Shape<A, B, C, D, E, F, G, H, I>
