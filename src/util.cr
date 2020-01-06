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

# link gmp to directly leverage integer exponentiation
@[Link("gmp")]
lib LibGMP
  fun mpz_powm_sec = __gmpz_powm_sec(rop : MPZ*, base : MPZ*, exp : MPZ*, mod : MPZ*)
end

# a collection of utilities for secp256k1 key management
module Secp256k1::Util
  # generic tool to encode single hex bytes as strings, e.g., "07"
  def self.to_padded_hex_01(i : Int32)
    hex = i.to_s 16
    while hex.size < 2
      hex = '0' + hex
    end
    return hex
  end

  # utility tool to ensure hex keys are always 32 bytes
  # it pads the number with leading zeros if not
  def self.to_padded_hex_32(i : BigInt)
    hex = i.to_s 16
    while hex.size < 64
      hex = '0' + hex
    end
    return hex
  end

  # a helper to generate 32 pseudo-random bytes
  def self.new_private_key
    key = -999
    until key > 0
      key = Random::Secure.hex 32
      key = BigInt.new key, 16
    end
    return key % EC_ORDER_N
  end

  # exports the compressed public key from an ec point without prefix
  private def self.public_key_compressed(p : EC_Point)
    return to_padded_hex_32 p.x
  end

  # exports the compressed public key from an ec point with prefix 02 or 03
  def self.public_key_compressed_prefix(p : EC_Point)
    prefix = p.y % 2 === 1 ? "03" : "02"
    return "#{prefix}#{public_key_compressed p}"
  end

  # exports the uncompressed public key from an ec point without prefix
  def self.public_key_uncompressed(p : EC_Point)
    x = to_padded_hex_32 p.x
    y = to_padded_hex_32 p.y
    return "#{x}#{y}"
  end

  # exports the uncompressed public key from an ec point with prefix 04
  def self.public_key_uncompressed_prefix(p : EC_Point)
    return "04#{public_key_uncompressed p}"
  end

  # decodes a public key as ec point from a compressed public key string
  def self.decode_compressed_public_key(pub : String, prime = EC_PARAM_PRIME)
    # only proceed if we have 1 prefix byte and 32 coordinate bytes
    if pub.size === 66
      # the prefix is used to restore the y-coordinate
      prefix = pub[0, 2]
      if prefix === "02" || prefix === "03"
        # x is simply the coordinate
        x = BigInt.new pub[2, 64], 16

        # y is on our curve (x^3 + 7) ^ ((p + 1) / 4) % p
        a = x ** 3 % prime
        a = (a + 7) % prime
        e = ((prime + 1) // 4) % prime
        y = BigInt.new
        LibGMP.mpz_powm_sec(y, a, e, prime)

        # check which of the two possible y values is to be used
        parity = prefix.to_i - 2
        if y % 2 != parity
          y = -y % prime
        end
        return EC_Point.new x, y
      else
        raise "invalid prefix for compressed public key: #{prefix}"
      end
    else
      raise "malformed compressed public key (invalid key size: #{pub.size})"
    end
    i = BigInt.new -999
    return EC_Point.new i, i
  end

  # decodes a public key as ec point from an uncompressed public key string
  private def self.decode_uncompressed_public_key(pub : String)
    # remove the prefix as it's always `04` for uncompressed keys
    pub = pub[2, 128] if pub.size === 130

    # only proceed if we have 2 x 32 bytes
    if pub.size === 128
      x = BigInt.new pub[0, 64], 16
      y = BigInt.new pub[64, 64], 16
      return EC_Point.new x, y
    else
      raise "malformed uncompressed public key (invalid key size: #{pub.size})"
    end
    i = BigInt.new -999
    return EC_Point.new i, i
  end

  # detects public key type and tries to restore the ec point from it
  def self.restore_public_key(pub : String)
    case pub.size
    when 130, 128
      return decode_uncompressed_public_key pub
    when 66
      return decode_compressed_public_key pub
    else
      raise "unknown public key format (invalid key size: #{pub.size})"
    end
    i = BigInt.new -999
    return EC_Point.new i, i
  end

  # wrapper function to perform an ec multiplication with
  # the generator point and a provided private key
  def self.public_key_from_private(priv : BigInt)
    return Core.ec_mul EC_BASE_G, priv
  end
end
