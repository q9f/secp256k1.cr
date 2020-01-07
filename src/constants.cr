# Copyright 2019-2020 @q9f
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "big/big_int"

# Implements 256-bit `Secp256k1` Koblitz elliptic curve.
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
#
# `Secp256k1` has the characteristic prime `p`, it is defined over the prime field ℤ_p.
# Ref: [en.bitcoin.it/wiki/Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
module Secp256k1
  # The elliptic curve domain parameters over `F_p` associated with a Koblitz curve
  # Secp256k1 are specified by the sextuple `T = (p, a, b, G, n, h)` where the finite
  # field `F_p` is defined by the prime `p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1`.
  EC_PRIME_P = BigInt.new "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16

  # The curve `E`: `y^2 = x^3 + ax + b` over `F_p` is defined by `a = 0`. 
  # As the `a` constant is zero, the `ax` term in the curve equation is always zero,
  # hence the curve equation becomes `y^2 = x^3 + b`.
  EC_FACTOR_A = BigInt.new "00", 16

  # The curve `E`: `y^2 = x^3 + b` over `F_p` is defined by `b = 7`,
  # hence the curve equation becomes `y^2 = x^3 + 7`.
  EC_FACTOR_B = BigInt.new "07", 16

  # The `x`-coordinate of the base point `G`.
  EC_BASE_G_X = BigInt.new "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16

  # The `y`-coordinate of the base point `G`.
  EC_BASE_G_Y = BigInt.new "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16

  # The commonly used base point `G` coordinates `x`, `y`;
  # any other point that satisfies `y^2 = x^3 + 7` would also do.
  EC_BASE_G = EC_Point.new EC_BASE_G_X, EC_BASE_G_Y

  # The base point `G` in compressed form.
  EC_BASE_G_COMPRESSED = BigInt.new (Secp256k1::Util.public_key_compressed_prefix EC_BASE_G), 16

  # The base point `G` in uncompressed form.
  EC_BASE_G_UNCOMPRESSED = BigInt.new (Secp256k1::Util.public_key_uncompressed_prefix EC_BASE_G), 16

  # The order `n` of `G` defines the finite size of the Secp256k1 field `E`.
  EC_ORDER_N = BigInt.new "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16

  # The elliptic curve cofactor `h`.
  EC_COFACTOR_H = BigInt.new "01", 16
end
