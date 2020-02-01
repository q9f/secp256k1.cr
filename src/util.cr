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

# Links GMP to directly leverage integer exponentiation.
@[Link("gmp")]
lib LibGMP
  fun mpz_powm_sec = __gmpz_powm_sec(rop : MPZ*, base : MPZ*, exp : MPZ*, mod : MPZ*)
end

# A collection of utilities for `Secp256k1` key management, e.g., private key
# generation, public key conversions, key formatting, or hex padding.
module Secp256k1::Util
  # A generic utility to encode single hex bytes as strings, e.g., "07"
  #
  # Parameters:
  # * `i` (`Int32`): the integer to be formatted as padded hex byte.
  #
  # ```
  # Secp256k1::Util.to_padded_hex_01 7
  # # => "07"
  # ```
  def self.to_padded_hex_01(i : Int32)
    hex = i.to_s 16
    while hex.size < 2
      hex = '0' + hex
    end
    hex
  end

  # An utility tool to ensure hex keys are always 32 bytes;
  # it pads the number with leading zeros if it's shorter.
  #
  # Parameters:
  # * `i` (`BigInt`): the integer to be formatted as padded hex byte string.
  #
  # ```
  # Secp256k1::Util.to_padded_hex_32 BigInt.new 7
  # # => "0000000000000000000000000000000000000000000000000000000000000007"
  # ```
  def self.to_padded_hex_32(i : BigInt)
    hex = i.to_s 16
    while hex.size < 64
      hex = '0' + hex
    end
    hex
  end

  # A helper function to generate 32 pseudo-random bytes within the elliptic
  # curve field size of `EC_ORDER_N`.
  #
  # ```
  # Secp256k1::Util.new_private_key
  # # => "b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268"
  # ```
  def self.new_private_key
    key = -999
    until key > 0
      key = Random::Secure.hex 32
      key = BigInt.new key, 16
    end
    key % EC_ORDER_N
  end

  # Exports the compressed public key from an ec point without prefix.
  #
  # The compressed public key without prefix is just the `x` coordinate
  # of the public key and **cannot** be recovered as full public key.
  # This is just a helper function and should not be used unless you
  # know why you want to do this.
  #
  # In most cases, you are looking for `public_key_compressed_prefix`.
  #
  # Parameters:
  # * `p` (`ECPoint`): the public key point which shall be compressed.
  #
  # ```
  # Secp256k1::Util.public_key_compressed my_public_key
  # # => "d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a"
  # ```
  private def self.public_key_compressed(p : ECPoint)
    to_padded_hex_32 p.x
  end

  # Exports the compressed public key from an `ECPoint` with either the
  # prefix `"02"` or `"03"`.
  #
  # The prefix can be later used to recover the `y` coordinate of the public key,
  # see `decode_compressed_public_key`. `Bitcoin` uses this format
  # to generate shorter addresses as compared to using uncompressed keys.
  #
  # Parameters:
  # * `p` (`ECPoint`): the public key point which shall be compressed.
  #
  # ```
  # Secp256k1::Util.public_key_compressed_prefix my_public_key
  # # => "03d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a"
  # ```
  def self.public_key_compressed_prefix(p : ECPoint)
    prefix = p.y % 2 === 1 ? "03" : "02"
    "#{prefix}#{public_key_compressed p}"
  end

  # Exports the uncompressed public key from an `ECPoint` without prefix.
  #
  # `Ethereum` uses this format to generate addresses. For prefixed
  # uncompressed public keys, see `public_key_uncompressed_prefix`.
  #
  # Parameters:
  # * `p` (`ECPoint`): the public key point which shall be uncompressed.
  #
  # ```
  # Secp256k1::Util.public_key_uncompressed my_public_key
  # # => "d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5"
  # ```
  def self.public_key_uncompressed(p : ECPoint)
    x = to_padded_hex_32 p.x
    y = to_padded_hex_32 p.y
    "#{x}#{y}"
  end

  # Exports the uncompressed public key from an `ECPoint` with prefix `"04"`.
  #
  # `Bitcoin` uses this format to generate uncompressed addresses.
  # For unprefixed public keys, see `public_key_uncompressed`.
  #
  # Parameters:
  # * `p` (`ECPoint`): the public key point which shall be uncompressed.
  #
  # ```
  # Secp256k1::Util.public_key_uncompressed_prefix my_public_key
  # # => "04d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5"
  # ```
  def self.public_key_uncompressed_prefix(p : ECPoint)
    "04#{public_key_uncompressed p}"
  end

  # Decodes a public key as `ECPoint` from a compressed public key string.
  #
  # If unsure, `restore_public_key` should be used.
  #
  # Parameters:
  # * `pub` (`String`): the public key in prefixed compressed format.
  # * `prime` (`BigInt`): the prime number that shapes the field, default: `EC_PRIME_P`.
  #
  # ```
  # Secp256k1::Util.decode_compressed_public_key "03d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a"
  # ```
  #
  # Returns an `ECPoint` containing the public key.
  #
  # Raises if compressed public key is malformed or comes with invalid prefix.
  def self.decode_compressed_public_key(pub : String, prime = EC_PRIME_P)
    # Only proceed if we have one prefix byte and 32 coordinate bytes.
    if pub.size === 66
      # The prefix is used to restore the `y`-coordinate.
      prefix = pub[0, 2]
      if prefix === "02" || prefix === "03"
        # `x` is simply the coordinate.
        x = BigInt.new pub[2, 64], 16

        # `y` is on our curve `(x^3 + 7) ^ ((p + 1) / 4) % p`
        a = x ** 3 % prime
        a = (a + 7) % prime
        e = ((prime + 1) // 4) % prime
        y = BigInt.new
        LibGMP.mpz_powm_sec(y, a, e, prime)

        # Check which of the two possible `y` values is to be used.
        parity = prefix.to_i - 2
        if y % 2 != parity
          y = -y % prime
        end
        ECPoint.new x, y
      else
        raise "invalid prefix for compressed public key: #{prefix}"
      end
    else
      raise "malformed compressed public key (invalid key size: #{pub.size})"
    end
  end

  # Decodes a public key as `ECPoint` from an uncompressed public key string.
  #
  # If unsure, `restore_public_key` should be used.
  #
  # Parameters:
  # * `pub` (`String`): the public key in any uncompressed format.
  #
  # ```
  # Secp256k1::Util.decode_uncompressed_public_key "04d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5"
  # ```
  #
  # Returns an `ECPoint` containing the public key.
  #
  # Raises if uncompressed public key is malformed.
  private def self.decode_uncompressed_public_key(pub : String)
    # Remove the prefix as it's always `"04"` for uncompressed keys.
    pub = pub[2, 128] if pub.size === 130

    # Only proceed if we have two times 32 bytes (`x`, `y`).
    if pub.size === 128
      x = BigInt.new pub[0, 64], 16
      y = BigInt.new pub[64, 64], 16
      ECPoint.new x, y
    else
      raise "malformed uncompressed public key (invalid key size: #{pub.size})"
    end
  end

  # Detects public key type and tries to restore the `ECPoint` from it.
  #
  # Parameters:
  # * `pub` (`String`): the public key in any format.
  # * `prime` (`BigInt`): the prime number that shapes the field, default: `EC_PRIME_P`.
  #
  # ```
  # Secp256k1::Util.restore_public_key "d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5"
  # ```
  #
  # Returns an `ECPoint` containing the public key.
  #
  # Raises if public key format is unknown.
  def self.restore_public_key(pub : String, prime = EC_PRIME_P)
    case pub.size
    when 130, 128
      decode_uncompressed_public_key pub
    when 66
      decode_compressed_public_key pub, prime
    else
      raise "unknown public key format (invalid key size: #{pub.size})"
    end
  end

  # Gets a public key from a private key.
  #
  # This is basically a wrapper function to perform an elliptic curve
  # multiplication with the generator point `g` and a provided private key `priv`.
  #
  # Parameters:
  # * `priv` (`BigInt`): the private key to be used.
  #
  # ```
  # Secp256k1::Util.public_key_from_private BigInt.new("b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268", 16)
  # ```
  #
  # Returns an `ECPoint` containing the public key.
  def self.public_key_from_private(priv : BigInt)
    Core.ec_mul EC_BASE_G, priv
  end
end
