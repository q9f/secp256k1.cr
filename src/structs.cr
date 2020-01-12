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
  # Implements a `Secp256k1` key pair containing a private and a public key.
  #
  # Properties:
  # * `private_key` (`BigInt`): the secret as known as the private key.
  # * `public_key` (`EC_Point`): the point on the elliptic curve as known as the public key.
  #
  # ```
  # key = Secp256k1::Keypair.new
  # key.get_secret
  # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
  # key.to_s
  # # => "e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b7d9011bb589e883d8a7947cfb37dc6b3c8beae9c614cab4a83009bd9d8732a9f"
  # ```
  class Keypair
    # The secret as known as the private key.
    property private_key : BigInt

    # The point on the elliptic curve as known as the public key.
    property public_key : EC_Point

    # Generates a new keypair using a random private key.
    #
    # ```
    # key = Secp256k1::Keypair.new
    # # => #<Secp256k1::Keypair:0x7f8be5611d80>
    # ```
    def initialize
      @private_key = Util.new_private_key
      @public_key = Util.public_key_from_private @private_key
    end

    # Generates a new keypair using a provided private key.
    #
    # Parameters:
    # * `private_key` (`BigInt`): the secret as known as the private key.
    #
    # ```
    # key = Secp256k1::Keypair.new BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
    # # => #<Secp256k1::Keypair:0x7f8be5611d80>
    # ```
    def initialize(@private_key)
      @public_key = Util.public_key_from_private @private_key
    end

    # Gets the private key as hexadecimal formatted string literal.
    #
    # ```
    # key.get_secret
    # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
    # ```
    def get_secret
      return Util.to_padded_hex_32 @private_key
    end

    # Gets the key formatted as uncompressed public key string.
    #
    # ```
    # key.to_s
    # # => "e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b7d9011bb589e883d8a7947cfb37dc6b3c8beae9c614cab4a83009bd9d8732a9f"
    # ```
    def to_s
      return Util.public_key_uncompressed @public_key
    end
  end

  # A point in the two-dimensional space of an elliptic curve.
  #
  # Properties:
  # * `x` (`BigInt`): the position on the x-axis.
  # * `y` (`BigInt`): the position on the y-axis.
  #
  # ```
  # p = EC_Point.new BigInt.new(0), BigInt.new(0)
  # p.x
  # # => 0
  # p.y
  # # => 0
  # ```
  struct EC_Point
    # The position on the x-axis.
    property x : BigInt

    # The position on the y-axis.
    property y : BigInt

    # An EC_Point always requires two coordinates `x`, `y`.
    #
    # Parameters:
    # * `x` (`BigInt`): the position on the x-axis.
    # * `y` (`BigInt`): the position on the y-axis.
    def initialize(@x : BigInt, @y : BigInt)
    end
  end

  # A basic ECDSA Signature containing a random point `r` and the
  # signature proof `s`.
  #
  # See: `Signature` for signature generation.
  #
  # Properties:
  # * `r` (`BigInt`): the `x` coordinate of a random point `R`.
  # * `s` (`BigInt`): the signature proof of a message.
  #
  # ```
  # sig = ECDSA_Signature.new r.x, proof
  # ```
  struct ECDSA_Signature
    # The `x` coordinate of a random point `R`.
    property r : BigInt

    # The signature proof of a message.
    property s : BigInt

    # A signature always requires the random point `r` and the signature proof `s`.
    #
    # Parameters:
    # * `r` (`BigInt`): the `x` coordinate of a random point `R`.
    # * `s` (`BigInt`): the signature proof of a message.
    def initialize(@r : BigInt, @s : BigInt)
    end
  end
end
