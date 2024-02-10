package com.github.traderjoe95.mls.protocol.crypto.impl

import com.github.traderjoe95.mls.protocol.crypto.Hash

internal class HashProvider(val hash: HashFunction) : Hash.Provider() {
  override fun hash(input: ByteArray): ByteArray =
    ByteArray(hash.hashLen.toInt()).also { out ->
      hash.createDigest().apply {
        update(input, 0, input.size)
        doFinal(out, 0)
      }
    }
}
