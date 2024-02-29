package com.github.traderjoe95.mls.protocol.message

import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal

typealias HandshakeContent = Content.Handshake<*>
typealias AuthHandshakeContent = AuthenticatedContent<HandshakeContent>

typealias HandshakeMessage = GroupMessage<HandshakeContent>
typealias CommitMessage = GroupMessage<Commit>
typealias ProposalMessage = GroupMessage<Proposal>
typealias ApplicationMessage = PrivateMessage<ApplicationData>

typealias MlsHandshakeMessage = MlsMessage<HandshakeMessage>
typealias MlsProposalMessage = MlsMessage<ProposalMessage>
typealias MlsCommitMessage = MlsMessage<CommitMessage>
typealias MlsApplicationMessage = MlsMessage<ApplicationMessage>
