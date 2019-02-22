{{
      $Id:$
     Desc: SHA-256 test program
   Author: Perry Harrington
Copyright: (c) 2012 Perry Harrington
=======================================================================

This is a test program for the SHA-256 hash

}}
CON

_clkmode = xtal1 + pll16x
_xinfreq = 5_000_000

OBJ

pst: "Parallax Serial Terminal"
sha256: "sha-256-1"

VAR
  long digest
  long inscount

PUB main | i
  pst.start(115200)             'debug output

  pst.Newline
  pst.Str(String("SHA-256 hash test"))
  pst.Newline

  pst.Str(String("Start"))
  sha256.Start
  pst.Newline

  sha256.HashMessage(@msg,len)

  pst.Str(String("Read Digest: "))
  digest := sha256.ReadDigest

  repeat i from 0 to 7
    pst.Hex(long[digest][i],8)
    pst.Char(32)

  pst.Newline

  pst.Str(String("Instruction count: "))
  pst.Dec(sha256.getIns(@inscount)>>2)
  pst.Newline

  repeat
  ''do something

DAT
message byte "a","b","c",$00
length long 3
msg byte "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",$00
len long 56
