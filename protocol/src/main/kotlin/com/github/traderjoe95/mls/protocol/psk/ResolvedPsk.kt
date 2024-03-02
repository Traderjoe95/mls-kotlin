package com.github.traderjoe95.mls.protocol.psk

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.psk.PskLabel.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

data class ResolvedPsk(val pskId: PreSharedKeyId, val psk: Secret) {
  companion object {
    fun calculatePskSecret(
      cipherSuite: ICipherSuite,
      psks: List<ResolvedPsk>,
    ): Secret =
      with(cipherSuite) {
        psks.foldIndexed(zeroesNh) { idx, pskSecret, (pskId, psk) ->
          updatePskSecret(pskSecret, pskId, psk, idx, psks.size)
        }
      }

    internal fun ICipherSuite.updatePskSecret(
      pskSecret: Secret,
      pskId: PreSharedKeyId,
      psk: Secret,
      index: Int,
      count: Int,
    ): Secret =
      extract(
        expandWithLabel(
          extract(zeroesNh.bytes, psk),
          "derived psk",
          PskLabel(pskId, index, count).encodeUnsafe(),
          hashLen,
        ).bytes,
        pskSecret,
      )
  }
}
