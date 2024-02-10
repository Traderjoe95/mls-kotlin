@file:Suppress("MemberVisibilityCanBePrivate")

package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Struct
import com.github.traderjoe95.mls.codec.Struct1
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.Struct3
import com.github.traderjoe95.mls.codec.Struct4
import com.github.traderjoe95.mls.codec.Struct5
import com.github.traderjoe95.mls.codec.Struct6
import com.github.traderjoe95.mls.codec.Struct7
import com.github.traderjoe95.mls.codec.Struct8
import com.github.traderjoe95.mls.codec.Struct9
import com.github.traderjoe95.mls.codec.error.SelectError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.util.throwAnyError

inline fun <S : Struct?, T : StructT<S>> struct(
  name: String,
  crossinline block: Raise<SelectError>.(StructBuilder.Initial) -> StructBuilder<S, T>,
): T = throwAnyError { block(StructBuilder.InitialImpl(name)).buildStructT() }

inline fun <A, reified V : Struct1T.Shape<A>> Struct1T<A>.lift(crossinline up: (A) -> V): DataType<V> = lift(up) { (a) -> create(a) }

inline fun <A, reified V> Struct1T<A>.lift(
  crossinline up: (A) -> V,
  crossinline down: (V) -> Struct1<A>,
): DataType<V> = StructT.Lifted(this, { (a) -> up(a) }, { down(it) })

inline fun <A, B, reified V : Struct2T.Shape<A, B>> Struct2T<A, B>.lift(crossinline up: (A, B) -> V): DataType<V> =
  lift(up) { (a, b) -> create(a, b) }

inline fun <A, B, reified V> Struct2T<A, B>.lift(
  crossinline up: (A, B) -> V,
  crossinline down: (V) -> Struct2<A, B>,
): DataType<V> = StructT.Lifted(this, { (a, b) -> up(a, b) }, { down(it) })

inline fun <A, B, C, reified V : Struct3T.Shape<A, B, C>> Struct3T<A, B, C>.lift(crossinline up: (A, B, C) -> V): DataType<V> =
  lift(up) { (a, b, c) -> create(a, b, c) }

inline fun <A, B, C, reified V> Struct3T<A, B, C>.lift(
  crossinline up: (A, B, C) -> V,
  crossinline down: (V) -> Struct3<A, B, C>,
): DataType<V> = StructT.Lifted(this, { (a, b, c) -> up(a, b, c) }, { down(it) })

inline fun <A, B, C, D, reified V : Struct4T.Shape<A, B, C, D>> Struct4T<A, B, C, D>.lift(crossinline up: (A, B, C, D) -> V): DataType<V> =
  lift(up) { (a, b, c, d) -> create(a, b, c, d) }

inline fun <A, B, C, D, reified V> Struct4T<A, B, C, D>.lift(
  crossinline up: (A, B, C, D) -> V,
  crossinline down: (V) -> Struct4<A, B, C, D>,
): DataType<V> = StructT.Lifted(this, { (a, b, c, d) -> up(a, b, c, d) }, { down(it) })

inline fun <A, B, C, D, E, reified V : Struct5T.Shape<A, B, C, D, E>> Struct5T<A, B, C, D, E>.lift(
  crossinline up: (A, B, C, D, E) -> V,
): DataType<V> = lift(up) { (a, b, c, d, e) -> create(a, b, c, d, e) }

inline fun <A, B, C, D, E, reified V> Struct5T<A, B, C, D, E>.lift(
  crossinline up: (A, B, C, D, E) -> V,
  crossinline down: (V) -> Struct5<A, B, C, D, E>,
): DataType<V> = StructT.Lifted(this, { (a, b, c, d, e) -> up(a, b, c, d, e) }, { down(it) })

inline fun <A, B, C, D, E, F, reified V : Struct6T.Shape<A, B, C, D, E, F>> Struct6T<A, B, C, D, E, F>.lift(
  crossinline up: (A, B, C, D, E, F) -> V,
): DataType<V> = lift(up) { (a, b, c, d, e, f) -> create(a, b, c, d, e, f) }

inline fun <A, B, C, D, E, F, reified V> Struct6T<A, B, C, D, E, F>.lift(
  crossinline up: (A, B, C, D, E, F) -> V,
  crossinline down: (V) -> Struct6<A, B, C, D, E, F>,
): DataType<V> = StructT.Lifted(this, { (a, b, c, d, e, f) -> up(a, b, c, d, e, f) }, { down(it) })

inline fun <A, B, C, D, E, F, G, reified V : Struct7T.Shape<A, B, C, D, E, F, G>> Struct7T<A, B, C, D, E, F, G>.lift(
  crossinline up: (A, B, C, D, E, F, G) -> V,
): DataType<V> = lift(up) { (a, b, c, d, e, f, g) -> create(a, b, c, d, e, f, g) }

inline fun <A, B, C, D, E, F, G, reified V> Struct7T<A, B, C, D, E, F, G>.lift(
  crossinline up: (A, B, C, D, E, F, G) -> V,
  crossinline down: (V) -> Struct7<A, B, C, D, E, F, G>,
): DataType<V> = StructT.Lifted(this, { (a, b, c, d, e, f, g) -> up(a, b, c, d, e, f, g) }, { down(it) })

@Suppress("kotlin:S107")
inline fun <A, B, C, D, E, F, G, H, reified V : Struct8T.Shape<A, B, C, D, E, F, G, H>> Struct8T<A, B, C, D, E, F, G, H>.lift(
  crossinline up: (A, B, C, D, E, F, G, H) -> V,
): DataType<V> = lift(up) { (a, b, c, d, e, f, g, h) -> create(a, b, c, d, e, f, g, h) }

@Suppress("kotlin:S107")
inline fun <A, B, C, D, E, F, G, H, reified V> Struct8T<A, B, C, D, E, F, G, H>.lift(
  crossinline up: (A, B, C, D, E, F, G, H) -> V,
  crossinline down: (V) -> Struct8<A, B, C, D, E, F, G, H>,
): DataType<V> = StructT.Lifted(this, { (a, b, c, d, e, f, g, h) -> up(a, b, c, d, e, f, g, h) }, { down(it) })

@Suppress("kotlin:S107")
inline fun <A, B, C, D, E, F, G, H, I, reified V : Struct9T.Shape<A, B, C, D, E, F, G, H, I>> Struct9T<A, B, C, D, E, F, G, H, I>.lift(
  crossinline up: (A, B, C, D, E, F, G, H, I) -> V,
): DataType<V> = lift(up) { (a, b, c, d, e, f, g, h, i) -> create(a, b, c, d, e, f, g, h, i) }

@Suppress("kotlin:S107")
inline fun <A, B, C, D, E, F, G, H, I, V> Struct9T<A, B, C, D, E, F, G, H, I>.lift(
  crossinline up: (A, B, C, D, E, F, G, H, I) -> V,
  crossinline down: (V) -> Struct9<A, B, C, D, E, F, G, H, I>,
): DataType<V> =
  StructT.Lifted(
    this,
    { (a, b, c, d, e, f, g, h, i) -> up(a, b, c, d, e, f, g, h, i) },
    { down(it) },
  )
