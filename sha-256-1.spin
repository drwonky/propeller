{{
      $Id:$
     Desc: SHA-256 PASM implementation
   Author: Perry Harrington
Copyright: (c) 2012 Perry Harrington
=======================================================================

This object implements SHA-256 in PASM for the Propeller 1.

Message is assumed to be a chunk of memory, no scratch space is needed
at the end of the buffer, the SPIN functions handle chunking and
termination of the blocks.

This requires 1 COG and can process 4217 blocks per second.

}}
CON
  #1, hBlock, rDigest, hInit, rIns

VAR
  long  digest[8]
  long  buf[16]
  long  cog
  long  parm

PUB Start
  Stop
  parm := 0

  cog := cognew(@sha_256_entry,@parm) + 1

PUB Stop
  if cog
    cogstop(cog~ -1)

PUB HashBlock(blockptr)
  parm := hBlock
  repeat while parm
  parm := blockptr
  repeat while parm

PUB setParm(val)
  parm := val

PUB getIns(insPtr)
  parm := rIns
  repeat while parm
  parm := insPtr
  repeat while parm

  return long[insPtr]

PUB getParm
  return parm

PUB getBuf
  return @buf

PUB Clear
  longfill(@buf,0,16)

PUB Init | i
  Clear

  longfill(@digest,0,8)
  parm := hInit
  repeat while parm

PUB ReadDigest
  parm := rDigest
  repeat while parm
  parm := @digest
  repeat while parm
  return @digest

PUB FinalBlock(msgPtr,totalLength)
  buf[15] := htonl(totalLength << 3)

  HashBlock(@buf)

PUB do56(msgPtr,len,total)
  Clear
  bytemove(@buf,msgPtr,len)
  byte[@buf][len]:=$80
  FinalBlock(msgPtr,total)

PUB do56to64(msgPtr,len,total)
  bytemove(@buf,msgPtr,len)
  byte[@buf][len]:=$80
  HashBlock(@buf)
  Clear
  FinalBlock(@buf,total)

PUB HashMessage(msgPtr,len) | block
  Init

  if len < 56                                           'message can fit into 1 block
    do56(msgPtr,len,len)
  elseif len < 64
    do56to64(msgPtr,len,len)
  else
    repeat len >> 6              'break into 512 bit blocks
      HashBlock(msgPtr + block << 6)
      block++

    if (len - block << 6 < 56)
      do56(msgPtr + block << 6,len - block << 6, len)
    else
      do56to64(msgPtr + block << 6, len - block << 6, len)

PUB htonl(val)
  result := ((val & $FF) << 24) | ((val & $FF00) << 8) | ((val & $FF_0000) >> 8) | ((val & $FF00_0000) >> 24)

DAT
              org

sha_256_entry
              rdlong    cmd,par                 wz
if_z          jmp       #sha_256_entry


              cmp       cmd,#hInit              wz
if_z          call      #sha_256_init

              cmp       cmd,#rDigest            wz
if_z          call      #sha_256_wDigest

              cmp       cmd,#hBlock             wz
if_z          call      #sha_256_block

              cmp       cmd,#rIns               wz
if_z          call      #sha_256_profile

              jmp       #sha_256_entry

sha_256_profile
              wrlong    null,par
:loop         rdlong    cmd,par                 wz
if_z          jmp       #:loop

              wrlong    ins,cmd

              wrlong    null,par

sha_256_profile_ret     ret

sha_256_wDigest
              wrlong    null,par
:loop         rdlong    cmd,par                 wz
if_z          jmp       #:loop

              mov       _cnt,#8
              movd      :loop1, #_h
              mov       tmp,#_h

:loop1        wrlong    _h,cmd
              add       cmd,#4
              add       tmp,#1
              movd      :loop1,tmp
              djnz      _cnt,#:loop1

              wrlong    null,par

sha_256_wDigest_ret     ret

sha_256_init
              movs      :init_h, #hash
              movd      :init_h, #_h
              mov       _cnt,#8

:init_h       mov       _h+0, hash+0               'copy the hash constants to working location
              add       :init_h,h201
              djnz      _cnt,#:init_h

              wrlong    null,par

sha_256_init_ret        ret

sha_256_block
              wrlong    null,par
:loop         rdlong    cmd,par                 wz
if_z          jmp       #:loop

              neg       ins,cnt

              movd      :cp_msg,#w              'reset self modifying pointers
              movs      :set_s0,#w+1
              movs      :set_s1,#w+14
              movs      :i16,#w
              movs      :i7,#w+9
              movd      :w16,#w+16
              movd      :init_ah,#a
              movs      :init_ah,#_h
              movs      :fetch_k,#k
              movs      :fetch_w,#w
              movs      :save_h,#a
              movd      :save_h,#_h

              mov       _cnt,#16                'setup src and dst to copy 16 longs
:fetch_msg    rdlong    ltl,cmd                 'copy chunk from hub memory
              add       cmd,#4
              call      #swap
:cp_msg       mov       w,big
              add       :cp_msg,h200
              djnz      _cnt,#:fetch_msg

              mov       _cnt,#8
:init_ah      mov       a,_h
              add       :init_ah,h201
              djnz      _cnt,#:init_ah

              mov       _cnt,#64                'repeat 64
:init_w       cmp       _cnt,#17 wc             'merge w init loop with processing loop
if_c          jmp       #:hash_loop

:set_s0       mov       t0,w+1                  's0:=w[i-15] >> 7 ^ w[i-15] >> 18 ^ w[i-15] >> 3
              add       :set_s0,#1

              mov       tmp,t0
              ror       tmp,#7
              mov       s0,tmp
              ror       tmp,#11
              xor       s0,tmp
              mov       tmp,t0
              shr       tmp,#3
              xor       s0,tmp

:set_s1       mov       t0,w+14                 's1:=w[i-2] >> 17 ^ w[i-2] >> 19 ^ w[i-2] >> 10
              add       :set_s1,#1

              mov       tmp,t0
              ror       tmp,#17
              mov       s1,tmp
              ror       tmp,#2
              xor       s1,tmp
              mov       tmp,t0
              shr       tmp,#10
              xor       s1,tmp

:i16          mov       t0,w                    'i-16
              add       :i16,#1

:i7           add       t0,w+9                  'i-7
              add       :i7,#1

              add       t0,s0
              add       t0,s1

:w16          mov       w+16,t0                 'w[i]:=w[i-16] + s0 + w[i-7] + s1
              add       :w16,h200

:hash_loop    mov       tmp,a                   's0:=a >>> 2 ^ a >>> 13 ^ a >>> 22
              ror       tmp,#2
              mov       s0,tmp
              ror       tmp,#11
              xor       s0,tmp
              ror       tmp,#9
              xor       s0,tmp

              mov       t1,a                   'maj:=a & b ^ b & c ^ c & a
              xor       t1,b
              and       t1,c
              mov       tmp,a
              and       tmp,b
              add       t1,tmp

              add       t1,s0                   't1:=s0 + maj

              mov       tmp,e                   's1:=e >>> 6 ^ e >>> 11 ^ e >>> 25
              ror       tmp,#6
              mov       s1,tmp
              ror       tmp,#5
              xor       s1,tmp
              ror       tmp,#14
              xor       s1,tmp

              mov       t0,g                    'ch:=e & f ^ !e & g
              xor       t0,f
              and       t0,e
              xor       t0,g

:fetch_k      add       t0,k                    'k[i]
              add       :fetch_k,#1

:fetch_w      add       t0,w                    'w[i]
              add       :fetch_w,#1

              add       t0,h                    't0:=h + s1 + ch + k[i] + w[i]
              add       t0,s1

              mov       h,g                     'h := g
              mov       g,f                     'g := f
              mov       f,e                     'f := e
              mov       e,d                     'e := d + t0
              add       e,t0
              mov       d,c                     'd := c
              mov       c,b                     'c := b
              mov       b,a                     'b := a
              mov       a,t0                    'a := t0 + t1
              add       a,t1

:loop_end     djnz      _cnt,#:init_w           'repeat 64

              mov       _cnt,#8
:save_h       add       _h,a                    'save a-h to _h for next round, on last round this is the digest
              add       :save_h,h201
              djnz      _cnt,#:save_h

              add       ins,cnt

              wrlong    null,par

sha_256_block_ret       ret

swap
              mov       big,ltl                 'x=$01234567
              rol       ltl,#8
              ror       big,#8
              and       ltl,h00FF00FF
              andn      big,h00FF00FF
              or        big,ltl                 'x=$67452301

swap_ret      ret

h00FF00FF     long $00FF00FF
h201          long %1_0000_0000_1
h200          long %1_0000_0000_0
null          long 0
ins           long 0

hash          long $6A09E667, $BB67AE85, $3C6EF372, $A54FF53A, $510E527F, $9B05688C, $1F83D9AB, $5BE0CD19

k             long $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5, $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5
              long $D807AA98, $12835B01, $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174
              long $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC, $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA
              long $983E5152, $A831C66D, $B00327C8, $BF597FC7, $C6E00BF3, $D5A79147, $06CA6351, $14292967
              long $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13, $650A7354, $766A0ABB, $81C2C92E, $92722C85
              long $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3, $D192E819, $D6990624, $F40E3585, $106AA070
              long $19A4C116, $1E376C08, $2748774C, $34B0BCB5, $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3
              long $748F82EE, $78A5636F, $84C87814, $8CC70208, $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2

w             res 64
_h            res 8
a             res 1
b             res 1
c             res 1
d             res 1
e             res 1
f             res 1
g             res 1
h             res 1
cmd           res 1
tmp           res 1
big           res 1
ltl           res 1
s0            res 1
s1            res 1
t0            res 1
t1            res 1
_cnt          res 1

