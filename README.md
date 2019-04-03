# propeller

This repository contains miscellaneous code I've written for the Parallax Propeller microcontroller.

The sha-256-1.spin is a complete implementation of the SHA-256 algorithm in PASM with a SPIN interface to call from.
This code was written for Parallax Semiconductor to be included in the Propeller 2 microcontroller.  The P2 went through a complete refactor since 2012 when this was written, thus the code was not used.

This code is licensed under the MIT license, you can do whatever you want with it.

There is a test program to validate the output of the routine.  At 80Mhz the routine can hash 4217 blocks per second -- it only uses 1 COG for this hashing, you could potentially launch multiple COGs and feed blocks in parallel to each COG and process up  to 29519 blocks per second, which is about 1.8MB per second.  1 COG has a throughput of ~263KB/s.
