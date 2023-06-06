# BIP 0340 Schnorr Signatures for secp256k1 for Raspberry Pi Pico

This is the code necessary to run schnorr signature on a Raspberry Pi Pico with MicroPython, coming from a bitcoin library. The only difference is that the `typing` library is not available on MicroPython, and that code has to be added manually. 

Source documentation [here](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#signing). 

Source code: [github](https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py).

Test vectors: [github](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).

## Run on Raspberry Pi Pico

Install [Thonny IDEA](https://thonny.org/) on your system.

Install MicroPython on the Raspberry Pi Pico following [these steps](https://www.raspberrypi.com/documentation/microcontrollers/micropython.html). 