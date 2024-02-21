package com.github.traderjoe95.mls.playground

import com.github.traderjoe95.mls.protocol.util.debug

suspend fun main() {
  val alice = Client("Alice")
  val bob = Client("Bob")
  val charlie = Client("Charlie")

  alice.generateKeyPackages(10U, Config.cipherSuite2)
  bob.generateKeyPackages(10U, Config.cipherSuite2)
  charlie.generateKeyPackages(10U, Config.cipherSuite2)

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

  val aliceGroup4 = aliceGroup3.reInit(Config.cipherSuite2).getOrThrow()

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

//  println("ALICE EPOCH 1 (Alice+Bob+Charlie) // RE-INIT:")
//  println("================================================================")
//  println(aliceNewGroup1.state.debug)
//  println()
}
