package com.github.traderjoe95.mls.protocol.message

import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Content

typealias HandshakeContent = Content.Handshake<*>
typealias AuthHandshakeContent = AuthenticatedContent<HandshakeContent>

typealias HandshakeMessage<Err> = GroupMessage<HandshakeContent, Err>
typealias ApplicationMessage = PrivateMessage<ApplicationData>
