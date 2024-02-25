package com.github.traderjoe95.mls.demo

import com.github.traderjoe95.mls.demo.client.Client
import com.github.traderjoe95.mls.protocol.util.debug

suspend fun main() {
  val alice = Client("Alice")
  val bob = Client("Bob")
  val charlie = Client("Charlie")

  alice.generateKeyPackages(10U, Config.cipherSuite)
  bob.generateKeyPackages(10U, Config.cipherSuite)
  charlie.generateKeyPackages(10U, Config.cipherSuite)

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

  val aliceBranchedGroup1 = aliceGroup3.branch("Alice", "Charlie").getOrThrow()

  println("ALICE EPOCH 1 (Alice+Charlie) // BRANCHED:")
  println("================================================================")
  println(aliceBranchedGroup1.state.debug)
  println()

  // Charlie receives the welcome for the branched group
  val charlieBranchedGroup1 = charlie.processNextMessage()!!

  println("Charlie EPOCH 1 (Alice+Charlie) // BRANCHED:")
  println("================================================================")
  println(charlieBranchedGroup1.state.debug)
  println()

  println()
  println("Sending messages in original group:")

  println("Alice: ")
  aliceGroup3.sendTextMessage("Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Bob: ")
  bobGroup2.sendTextMessage("Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlieGroup1.sendTextMessage("How are you, Bob?")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println("Bob: ")
  bobGroup2.sendTextMessage("I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlieGroup1.sendTextMessage("Good to hear!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()
  println()

  println()
  println("Sending messages in branched group:")

  println("Alice: ")
  aliceBranchedGroup1.sendTextMessage("Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlieBranchedGroup1.sendTextMessage("How are you, Alice?")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println("Alice: ")
  aliceBranchedGroup1.sendTextMessage("I'm fine, thanks! Now we can finally talk in private")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlieBranchedGroup1.sendTextMessage("Good to hear! Yes, at last")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()
}
