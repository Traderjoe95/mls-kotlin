package com.github.traderjoe95.mls.demo.util

import com.github.traderjoe95.mls.demo.getOrThrow
import com.github.traderjoe95.mls.demo.service.DeliveryService
import com.github.traderjoe95.mls.protocol.client.ActiveGroupClient

fun ActiveGroupClient<String>.makePublic() {
  DeliveryService.storeGroupInfo(groupInfo().getOrThrow())
}
