package com.github.traderjoe95.mls.interop.store

import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair

data class ExternalSigner(
  val signatureKeyPair: SignatureKeyPair,
  val credential: BasicCredential,
)
