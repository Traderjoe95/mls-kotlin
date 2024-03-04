package com.github.traderjoe95.mls.demo

import arrow.core.raise.either
import com.github.traderjoe95.mls.demo.client.Client
import com.github.traderjoe95.mls.demo.service.AuthenticationService
import com.github.traderjoe95.mls.demo.service.DeliveryService
import com.github.traderjoe95.mls.demo.util.makePublic
import com.github.traderjoe95.mls.protocol.client.ActiveGroupClient
import com.github.traderjoe95.mls.protocol.util.debug

suspend fun main() {
  val alice = Client("Alice")
  val bob = Client("Bob")
  val charlie = Client("Charlie")

  alice.generateKeyPackages(10U)
  bob.generateKeyPackages(10U)
  charlie.generateKeyPackages(10U)

  // Alice creates the group. At this point, she is the only member
  val aliceGroup = alice.createGroup().getOrThrow()
  aliceGroup.makePublic()
  println("ALICE EPOCH 0 (Only Alice):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  val bobGroup = bob.joinPublicGroup(aliceGroup.state.groupId).getOrThrow()

  alice.processNextMessage().getOrThrow()
  bobGroup.makePublic()

  val charlieGroup = charlie.joinPublicGroup(bobGroup.state.groupId).getOrThrow()

  alice.processNextMessage().getOrThrow()
  bob.processNextMessage().getOrThrow()

  println("ALICE EPOCH 2 (Alice+Charlie):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  println("Bob EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(bobGroup.state.debug)
  println()

  println("Charlie EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(charlieGroup.state.debug)
  println()

  val (aliceBranchedGroup, welcome) =
    aliceGroup.branch(
      either { alice.newKeyPackage(aliceGroup.cipherSuite) }.getOrThrow(),
      listOf(alice.getKeyPackageFor(aliceGroup.cipherSuite, "Charlie")),
    ).getOrThrow()
  DeliveryService.registerForGroup(aliceBranchedGroup.groupId, "Alice")

  welcome.forEach { (welcome, to) ->
    DeliveryService.sendMessageToIdentities(
      welcome.encoded,
      AuthenticationService.authenticateCredentials(
        to.map { it.leafNode.signaturePublicKey to it.leafNode.credential },
      ).map { it.getOrThrow() },
    )
  }

  println("ALICE EPOCH 1 (Alice+Charlie) // BRANCHED:")
  println("================================================================")
  println(aliceBranchedGroup.state.debug)
  println()

  // Charlie receives the welcome for the branched group
  val charlieBranchedGroup = charlie.processNextMessage().getOrThrow()!! as ActiveGroupClient<String>

  println("Charlie EPOCH 1 (Alice+Charlie) // BRANCHED:")
  println("================================================================")
  println(charlieBranchedGroup.state.debug)
  println()

  println()
  println("Sending messages in original group:")

  println("Alice: ")
  alice.sendMessage(aliceGroup.groupId, "Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieGroup.groupId, "How are you, Bob?")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieGroup.groupId, "Good to hear!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()
  println()

  println()
  println("Sending messages in branched group:")

  println("Alice: ")
  alice.sendMessage(aliceBranchedGroup.groupId, "Hello, this is Alice!")
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieBranchedGroup.groupId, "How are you, Alice?")
  print("  [Alice] ")
  alice.processNextMessage()

  println("Alice: ")
  alice.sendMessage(aliceBranchedGroup.groupId, "I'm fine, thanks! Now we can finally talk in private")
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieBranchedGroup.groupId, "Good to hear! Yes, at last")
  print("  [Alice] ")
  alice.processNextMessage()
}
