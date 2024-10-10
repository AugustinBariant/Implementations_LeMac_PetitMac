Implementation of LeMac and PetitMac
------------------------------------

In this project, you may find the implementations of two AES-based MACs presented at ToSC 2024 (https://tosc.iacr.org/index.php/ToSC/article/view/11619), LeMac and PetitMac. Each MAC is implemented in C (respectively in `lemac.c` and `petitmac.c`) and in python (in `lemac_petitmac.py`). A script that displays some test vectors is also provided, to ease further implementations.

Important note
--------------

There was a mistake in the specification of LeMac in the original paper:
the message schedule extraction from the memory was shifted by one
round.  This affects the security of the design: instead of guarantying
at least 26 active S-Boxes, it guaranties only at least 25 active
S-Boxes.  On the other hand, it does not affect the performances.

In this reference implementation, we have implemented the correct
design, and renamed the faulty MAC described in the initial paper as
LeMac-0.

Usage
-----

To compile this project, first download or clone this project, then dive into the main folder in a terminal and type:

```
make
```

**Note:** A processor supporting AES-NI instructions is required.

Then, to generate test vectors and verify the match between the C and python implementations, type:

```
python3 test_vectors.py
```

You can additionally generate other test vectors of LeMac and PetitMac
by adding calls to the `test` function with different keys, nonces, and
messages in `test_vectors.py`, with parameter `verbose=True`.


License
-------

The AES implementation from https://github.com/boppreh/aes is under the
MIT license.

The rest of the code is dedicated to the public domain under the CC0 license.
