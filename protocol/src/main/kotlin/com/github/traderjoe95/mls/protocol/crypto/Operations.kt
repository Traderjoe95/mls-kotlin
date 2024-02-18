package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.PskLabel
import com.github.traderjoe95.mls.protocol.types.crypto.PskLabel.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

context(ICipherSuite)
fun List<Pair<PreSharedKeyId, Secret>>.calculatePskSecret(): Secret {
  var pskSecret = zeroesNh
  var pskInput: Secret

  for (i in indices) {
    val (pskId, psk) = this[i]

    pskInput =
      expandWithLabel(
        extract(zeroesNh.key, psk),
        "derivedPsk",
        PskLabel(pskId, i, size).encodeUnsafe(),
        hashLen,
      )

    pskSecret = extract(pskInput.key, pskSecret)
  }

  return pskSecret
}
