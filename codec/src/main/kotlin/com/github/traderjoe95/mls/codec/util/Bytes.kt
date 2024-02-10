package com.github.traderjoe95.mls.codec.util

operator fun ByteArray.get(index: UInt): Byte = this[index.toInt()]

operator fun ByteArray.set(
  index: UInt,
  value: Byte,
) {
  this[index.toInt()] = value
}

operator fun ByteArray.get(indices: UIntRange): ByteArray = sliceArray(indices.toIntRange())
