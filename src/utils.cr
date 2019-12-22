# Copyright 2019 @q9f
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

# a collection of utilities for secp256k1 key management
module Secp256k1
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
  def self.public_key_compressed(p : EC_Point)
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

  # wrapper function to perform an ec multiplication with
  # the generator point and a provided private key
  def self.public_key_from_private(priv : BigInt)
    return ec_mul EC_BASE_G, priv
  end
end
