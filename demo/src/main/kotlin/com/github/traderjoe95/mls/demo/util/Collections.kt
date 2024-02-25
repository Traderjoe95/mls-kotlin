package com.github.traderjoe95.mls.demo.util

import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import java.util.concurrent.ConcurrentMap

operator fun <K : RefinedBytes<K>, V> Map<Int, V>.get(key: K): V? = this[key.hashCode]

inline fun <K : RefinedBytes<K>, V> Map<Int, V>.getOrElse(
  key: K,
  defaultValue: () -> V,
): V = getOrElse(key.hashCode, defaultValue)

operator fun <K : RefinedBytes<K>, V> MutableMap<Int, V>.set(
  key: K,
  value: V,
) {
  this[key.hashCode] = value
}

operator fun <K : RefinedBytes<K>, V> Map<Int, V>.contains(key: K): Boolean = key.hashCode in this

fun <K : RefinedBytes<K>, V> ConcurrentMap<Int, V>.compute(
  key: K,
  remappingFunction: (Int, V?) -> V?,
): V? = compute(key.hashCode(), remappingFunction)

operator fun <K : RefinedBytes<K>> Set<Int>.contains(key: K): Boolean = key.hashCode in this

fun <K : RefinedBytes<K>> MutableSet<Int>.add(key: K) = add(key.hashCode)
