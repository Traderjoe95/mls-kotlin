package com.github.traderjoe95.mls.codec

operator fun UIntRange.times(factor: UInt): UIntRange = (first * factor)..(last * factor)

operator fun UIntRange.div(divisor: UInt): UIntRange = (first / divisor)..(last / divisor)
