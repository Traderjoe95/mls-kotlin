package com.github.traderjoe95.mls.demo

import com.github.traderjoe95.mls.demo.client.Client
import com.github.traderjoe95.mls.protocol.util.debug

suspend fun main() {
  val alice = Client("Alice")
  val bob = Client("Bob")
  val charlie = Client("Charlie")

  alice.generateKeyPackages(10U, Config.reInitCipherSuite)
  bob.generateKeyPackages(10U, Config.reInitCipherSuite)
  charlie.generateKeyPackages(10U, Config.reInitCipherSuite)

  // Alice creates the group. At this point, she is the only member
  val aliceGroup1 = alice.createGroup(public = true).getOrThrow()
  println("ALICE EPOCH 0 (Only Alice):")
  println("================================================================")
  println(aliceGroup1.state.debug)
  println()

  val bobGroup1 = bob.joinPublicGroup(aliceGroup1.state.groupId).getOrThrow()
  val aliceGroup2 = alice.processNextMessage()!!

  println("ALICE EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println(aliceGroup2.state.debug)
  println()

  println("Bob EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println(bobGroup1.state.debug)
  println()

  bobGroup1.makePublic().getOrThrow()

  val charlieGroup1 = charlie.joinPublicGroup(bobGroup1.state.groupId).getOrThrow()
  val aliceGroup3 = alice.processNextMessage()!!
  val bobGroup2 = bob.processNextMessage()!!

  println("ALICE EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(aliceGroup3.state.debug)
  println()

  println("Bob EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(bobGroup2.state.debug)
  println()

  println("Charlie EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(charlieGroup1.state.debug)
  println()

  val aliceGroup4 = aliceGroup3.reInit(Config.reInitCipherSuite).getOrThrow()

  println("ALICE EPOCH 3 (Alice+Bob+Charlie) // SUSPENDED:")
  println("================================================================")
  println(aliceGroup4.state.debug)
  println()

  val bobGroup3 = bob.processNextMessage()!!
  val charlieGroup2 = charlie.processNextMessage()!!

  println("Bob EPOCH 3 (Alice+Bob+Charlie) // SUSPENDED:")
  println("================================================================")
  println(bobGroup3.state.debug)
  println()

  println("Charlie EPOCH 3 (Alice+Bob+Charlie) // SUSPENDED:")
  println("================================================================")
  println(charlieGroup2.state.debug)
  println()

  println("#####################################################################################################")
  println()

  // Bob can also send the welcome:
  val bobNewGroup1 = bobGroup3.createReInitGroup().getOrThrow()

  // Alice and Charlie receive the Welcome
  val aliceNewGroup1 = alice.processNextMessage()!!
  val charlieNewGroup1 = charlie.processNextMessage()!!

  println("Bob EPOCH 1 (Alice+Bob+Charlie) // RE-INIT:")
  println("================================================================")
  println(bobNewGroup1.state.debug)
  println()

  println("Alice EPOCH 1 (Alice+Bob+Charlie) // RE-INIT:")
  println("================================================================")
  println(aliceNewGroup1.state.debug)
  println()

  println("Charlie EPOCH 1 (Alice+Bob+Charlie) // RE-INIT:")
  println("================================================================")
  println(charlieNewGroup1.state.debug)
  println()

  println()
  println("Sending messages:")

  println("Alice: ")
  aliceNewGroup1.sendTextMessage("Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Bob: ")
  bobNewGroup1.sendTextMessage("Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlieNewGroup1.sendTextMessage("How are you, Bob?")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println("Bob: ")
  bobNewGroup1.sendTextMessage("I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlieNewGroup1.sendTextMessage("Good to hear!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()
}
