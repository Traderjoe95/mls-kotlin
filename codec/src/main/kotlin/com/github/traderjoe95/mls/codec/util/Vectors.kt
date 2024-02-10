package com.github.traderjoe95.mls.codec.util

inline val ByteArray.uSize: UInt
  get() = size.toUInt()

inline val String.uSize: UInt
  get() = encodeToByteArray().uSize

inline val List<*>.uSize: UInt
  get() = size.toUInt()
