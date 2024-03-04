package com.github.traderjoe95.mls.demo

import com.github.traderjoe95.mls.demo.client.Client
import com.github.traderjoe95.mls.demo.service.AuthenticationService
import com.github.traderjoe95.mls.demo.service.DeliveryService
import com.github.traderjoe95.mls.demo.util.makePublic
import com.github.traderjoe95.mls.protocol.client.ActiveGroupClient
import com.github.traderjoe95.mls.protocol.client.SuspendedGroupClient
import com.github.traderjoe95.mls.protocol.util.debug
import com.github.traderjoe95.mls.protocol.util.unsafe

suspend fun main() {
  val alice = Client("Alice")
  val bob = Client("Bob")
  val charlie = Client("Charlie")

  alice.generateKeyPackages(10U, cipherSuite = Config.reInitCipherSuite)
  bob.generateKeyPackages(10U, cipherSuite = Config.reInitCipherSuite)
  charlie.generateKeyPackages(10U, cipherSuite = Config.reInitCipherSuite)

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

  val reInitCommit = aliceGroup.triggerReInit(Config.reInitCipherSuite).getOrThrow()
  DeliveryService.sendMessageToGroup(reInitCommit, aliceGroup.groupId)

  val aliceGroupSuspended = alice.processNextMessage().getOrThrow()!! as SuspendedGroupClient<String>
  val bobGroupSuspended = bob.processNextMessage().getOrThrow()!! as SuspendedGroupClient<String>
  val charlieGroupSuspended = charlie.processNextMessage().getOrThrow()!! as SuspendedGroupClient<String>

  println("ALICE EPOCH 3 (Alice+Bob+Charlie) // SUSPENDED:")
  println("================================================================")
  println(aliceGroupSuspended.state.debug)
  println()

  println("Bob EPOCH 3 (Alice+Bob+Charlie) // SUSPENDED:")
  println("================================================================")
  println(bobGroupSuspended.state.debug)
  println()

  println("Charlie EPOCH 3 (Alice+Bob+Charlie) // SUSPENDED:")
  println("================================================================")
  println(charlieGroupSuspended.state.debug)
  println()

  println("#####################################################################################################")
  println()

  // Bob can also send the welcome:
  val (bobNewGroup, welcome) =
    bobGroupSuspended.resume(
      unsafe { bob.newKeyPackage(Config.reInitCipherSuite) },
      listOf(
        bob.getKeyPackageFor(Config.reInitCipherSuite, "Alice"),
        bob.getKeyPackageFor(Config.reInitCipherSuite, "Charlie"),
      ),
    ).getOrThrow()

  DeliveryService.registerForGroup(bobNewGroup.groupId, "Bob")

  welcome.forEach { (welcome, to) ->
    DeliveryService.sendMessageToIdentities(
      welcome.encoded,
      AuthenticationService.authenticateCredentials(
        to.map { it.leafNode.signaturePublicKey to it.leafNode.credential },
      ).map { it.getOrThrow() },
    )
  }

  // Alice and Charlie receive the Welcome
  val aliceNewGroup = alice.processNextMessage().getOrThrow()!! as ActiveGroupClient<String>
  val charlieNewGroup = charlie.processNextMessage().getOrThrow()!! as ActiveGroupClient<String>

  println("Bob EPOCH 1 (Alice+Bob+Charlie) // RE-INIT:")
  println("================================================================")
  println(bobNewGroup.state.debug)
  println()

  println("Alice EPOCH 1 (Alice+Bob+Charlie) // RE-INIT:")
  println("================================================================")
  println(aliceNewGroup.state.debug)
  println()

  println("Charlie EPOCH 1 (Alice+Bob+Charlie) // RE-INIT:")
  println("================================================================")
  println(charlieNewGroup.state.debug)
  println()

  println()
  println("Sending messages:")

  println("Alice: ")
  alice.sendMessage(aliceNewGroup.groupId, "Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Bob: ")
  bob.sendMessage(bobNewGroup.groupId, "Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieNewGroup.groupId, "How are you, Bob?")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println("Bob: ")
  bob.sendMessage(bobNewGroup.groupId, "I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieNewGroup.groupId, "Good to hear!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()
}
