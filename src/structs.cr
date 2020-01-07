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

# Implements 256-bit `Secp256k1` Koblitz elliptic curve.
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
#
# `Secp256k1` has the characteristic prime `p`, it is defined over the prime field ℤ_p.
# Ref: [en.bitcoin.it/wiki/Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
module Secp256k1
  # A point in the two-dimensional space of an elliptic curve.
  #
  # Properties:
  # * `x` (`BigInt`): the position on the x-axis.
  # * `y` (`BigInt`): the position on the y-axis.
  #
  # ```
  # P = EC_Point.new BigInt.new(0), BigInt.new(0)
  # p.x # => 0
  # p.y # => 0
  # ```
  class EC_Point
    # The position on the x-axis.
    property x : BigInt

    # The position on the y-axis.
    property y : BigInt

    # An EC_Point always requires two coordinates `x`, `y`.
    #
    # Properties:
    # * `x` (`BigInt`): the position on the x-axis.
    # * `y` (`BigInt`): the position on the y-axis.
    def initialize(@x : BigInt, @y : BigInt)
    end
  end

  # A basic ECDSA Signature containing a random point `r` and the
  # signature proof `s`.
  #
  # See: `Secp256k1::Signature` for signature generation.
  #
  # Properties:
  # * `r` (`BigInt`): the `x` coordinate of a random point `R`.
  # * `s` (`BigInt`): the signature proof of a message.
  #
  # ```
  # sig = ECDSA_Signature.new r.x, proof
  # ```
  class ECDSA_Signature
    # The `x` coordinate of a random point `R`.
    property r : BigInt

    # The signature proof of a message.
    property s : BigInt

    # A signature always requires the random point `r` and the signature proof `s`.
    #
    # Properties:
    # * `r` (`BigInt`): the `x` coordinate of a random point `R`.
    # * `s` (`BigInt`): the signature proof of a message.
    def initialize(@r : BigInt, @s : BigInt)
    end
  end
end
