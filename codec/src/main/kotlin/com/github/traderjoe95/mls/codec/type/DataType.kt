package com.github.traderjoe95.mls.codec.type

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.mapFirst
import com.github.traderjoe95.mls.codec.util.throwAnyError

inline fun <V, D> DataType<D>.derive(
  crossinline up: context(Raise<DecoderError>)
  (D) -> V,
  crossinline down: context(Raise<EncoderError>)
  (V) -> D,
  name: String? = null,
): DataType<V> = DataType.Derived.using(this, up, down, name)

fun <V> DataType<V>.named(name: String): DataType<V> = DataType.Named(this, name)

interface DataType<V> {
  val name: String
  val encodedLength: UInt?
    get() = null

  context(Raise<EncoderError>)
  fun encode(value: V): ByteArray

  fun encodeUnsafe(value: V): ByteArray = throwAnyError { encode(value) }

  context(Raise<DecoderError>)
  fun decode(bytes: Slice): Pair<V, Slice>

  companion object {
    context(Raise<DecoderError>)
    fun <V> Pair<V, Slice>.done(): V = second.ensureFinished().let { first }
  }

  class Named<V>(val type: DataType<V>, override val name: String) : DataType<V> by type

  abstract class Derived<V, D>(
    internal val base: DataType<D>,
    name: String? = null,
  ) : DataType<V> {
    override val name: String = name ?: base.name
    override val encodedLength: UInt?
      get() = base.encodedLength

    context(Raise<DecoderError>)
    abstract fun convertUp(value: D): V

    context(Raise<EncoderError>)
    abstract fun convertDown(value: V): D

    context(Raise<EncoderError>)
    final override fun encode(value: V): ByteArray = base.encode(convertDown(value))

    context(Raise<DecoderError>)
    final override fun decode(bytes: Slice): Pair<V, Slice> = base.decode(bytes).mapFirst { convertUp(it) }

    override fun toString(): String = base.toString()

    companion object {
      inline fun <V, D> using(
        base: DataType<D>,
        crossinline up: context(Raise<DecoderError>)
        (D) -> V,
        crossinline down: context(Raise<EncoderError>)
        (V) -> D,
        name: String? = null,
      ): Derived<V, D> =
        object : Derived<V, D>(base, name) {
          context(Raise<DecoderError>)
          override fun convertUp(value: D): V = up(this@Raise, value)

          context(Raise<EncoderError>)
          override fun convertDown(value: V): D = down(this@Raise, value)
        }
    }
  }
}
