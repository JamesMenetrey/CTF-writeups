val serialCharset = '0' to '9' union('A' to 'Z') union('a' to 'z')

def shake(a1: Char, a2: Int): Boolean = {
  val v3 = (a1 & 0xF0) >> 4
  v3 == (a1 & 0xF) && v3 == a2
}

def bruteForceShake(a2: Int): Char = {
  val r = for (c <- serialCharset if shake(c, a2)) yield c
  r.head
}

def bruteForce5thAnd11th(): (Char, Char) = {
  val r = for {
    c1 <- serialCharset
    c2 <- serialCharset
    if (c1 ^ c2) == 0x1b
    if (c1 + c2) == 0xa3
    if (c2 - c1) == 5
  } yield (c1, c2)

  r.head
}

object SerialChars {
  val (_5, _11) = bruteForce5thAnd11th()

  lazy val _0 = _2 - 0x20
  lazy val _1 = '0'
  lazy val _2 = bruteForceShake(7)
  lazy val _3 = '_'
  lazy val _4 = bruteForceShake(6)
  lazy val _6 = _1
  lazy val _7 = _4 - 0x20
  lazy val _8 = 1 + 0x30
  lazy val _9 = _10 - 1
  lazy val _10 = _4 + 2
  lazy val _12 = 3 + 0x30
  lazy val _13 = 'r'
  lazy val _14 = (1 << 5) + 1
  lazy val _15 = _14
}

import SerialChars._

val serial = Array(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15).map(_.toChar).mkString("")

println(s"The serial is: $serial")