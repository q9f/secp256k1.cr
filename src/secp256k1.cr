# Copyright 2019-2022 Afr Schoe @q9f
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
require "openssl/digest"
require "openssl/hmac"
require "sha3"

require "./secp256k1/context"
require "./secp256k1/curve"
require "./secp256k1/key"
require "./secp256k1/num"
require "./secp256k1/point"
require "./secp256k1/signature"
require "./secp256k1/util"
require "./secp256k1/version"

# Provides the `Secp256k1` module with the elliptic curve  parameters
# used by the `Bitcoin`, `Ethereum`, and `Polkadot` blockchains. It's
# primarily used to generate key-pairs as well as signing messages and
# recoverying signatures.
#
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
module Secp256k1
  # The elliptic curve domain parameters over `F_p` associated with a
  # Koblitz curve `Secp256k1` are specified by the sextuple
  # `T = (p, a, b, G, n, h)` where the finite field `F_p` is defined by
  # the prime `p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1`.
  P = Num.new "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"

  # The order `n` of `G` defines the finite size of the Secp256k1 field `E`.
  N = Num.new "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

  # A commonly used base point `G` with coordinates `x` and `y`
  # satisfying `y^2 = x^3 + 7`.
  G = Point.new(
    Num.new("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    Num.new("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
  )
end
