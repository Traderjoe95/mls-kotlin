package com.github.traderjoe95.mls.codec.util

inline fun <A, B, C> Pair<A, B>.mapFirst(mapper: (A) -> C): Pair<C, B> = mapper(first) to second
