package com.github.traderjoe95.mls.protocol.group

import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent

fun <C : Content<C>> GroupState.createFramedContent(
  content: C,
  authenticatedData: ByteArray = byteArrayOf(),
): FramedContent<C> = FramedContent.createMember(groupContext, content, leafIndex, authenticatedData)
