package com.github.traderjoe95.mls.protocol.crypto.impl

import com.github.traderjoe95.mls.codec.Struct3
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint8
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve
import java.math.BigInteger

val P256_POINT_T: DataType<ECPoint> =
  struct("UncompressedPointRepresentation") {
    it.field("legacy_form", uint8, uint8(4U))
      .field("X", opaque[32U])
      .field("Y", opaque[32U])
  }.lift(
    { _, x, y -> SecP256R1Curve().createPoint(BigInteger(x), BigInteger(y)) },
    { Struct3(uint8(4U), it.xCoord.encoded, it.yCoord.encoded) },
  )

val P384_POINT_T: DataType<ECPoint> =
  struct("UncompressedPointRepresentation") {
    it.field("legacy_form", uint8, uint8(4U))
      .field("X", opaque[48U])
      .field("Y", opaque[48U])
  }.lift(
    { _, x, y -> SecP384R1Curve().createPoint(BigInteger(x), BigInteger(y)) },
    { Struct3(uint8(4U), it.xCoord.encoded, it.yCoord.encoded) },
  )

val P521_POINT_T: DataType<ECPoint> =
  struct("UncompressedPointRepresentation") {
    it.field("legacy_form", uint8, uint8(4U))
      .field("X", opaque[66U])
      .field("Y", opaque[66U])
  }.lift(
    { _, x, y -> SecP521R1Curve().createPoint(BigInteger(x), BigInteger(y)) },
    { Struct3(uint8(4U), it.xCoord.encoded, it.yCoord.encoded) },
  )
