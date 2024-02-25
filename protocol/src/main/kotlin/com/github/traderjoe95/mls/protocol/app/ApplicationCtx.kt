package com.github.traderjoe95.mls.protocol.app

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.service.DeliveryService
import com.github.traderjoe95.mls.protocol.types.GroupId

interface ApplicationCtx<Identity : Any> : AuthenticationService<Identity>, DeliveryService<Identity> {
  fun newKeyPackage(cipherSuite: CipherSuite): KeyPackage.Private

  fun getKeyPackage(ref: KeyPackage.Ref): KeyPackage.Private?

  fun groupIdExists(id: GroupId): Boolean
}
