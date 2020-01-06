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

require "openssl"
require "sha3"

# wraps various hasing functions for convenience
module Secp256k1::Crypto
  # the base-58 alphabet (for bitcoin)
  BASE_58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  # the base-57 alphabet (for mini private keys)
  BASE_57 = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  # operating a sha3-256 hash on the byte array
  def self.sha3(h : String)
    sha3 = Digest::SHA3.new(256)
    b = hex_to_bin h
    return sha3.update(b).hexdigest
  end

  # operating a sha3-256 hash on the actual string literal
  def self.sha3_string(h : String)
    sha3 = Digest::SHA3.new(256)
    return sha3.update(h).hexdigest
  end

  # operating a keccak-256 hash on the byte array
  def self.keccak256(h : String)
    keccak = Digest::Keccak3.new(256)
    b = hex_to_bin h
    return keccak.update(b).hexdigest
  end

  # operating a keccak-256 hash on the actual string literal
  def self.keccak256_string(h : String)
    keccak = Digest::Keccak3.new(256)
    return keccak.update(h).hexdigest
  end

  # operating a sha2-256 hash on the byte array
  def self.sha256(h : String)
    b = hex_to_bin h
    return OpenSSL::Digest.new("SHA256").update(b).hexdigest
  end

  # operating a sha2-256 hash on the actual string literal
  def self.sha256_string(h : String)
    return OpenSSL::Digest.new("SHA256").update(h).hexdigest
  end

  # operating a ripemd-160 hash on the byte array
  def self.ripemd160(h : String)
    b = hex_to_bin h
    return OpenSSL::Digest.new("RIPEMD160").update(b).hexdigest
  end

  # decode a hex string from base-58
  def self.base58_decode(s : String)
    # cycle through each character of string
    index = 0
    decimal = BigInt.new 0
    while index < s.size
      b58_char = s[index]
      position = BASE_58.index(b58_char)
      if !position.nil?
        decimal = decimal * 58 + position
        index += 1
      else
        raise "cannot decode, invalid base58 character: '#{s[index]}'"
        return "-999"
      end
    end

    # count leading 1s and pad with "00" bytes
    hex = decimal.to_s 16
    leading = 0
    while s[leading] === '1'
      leading += 1
      hex = "00#{hex}"
    end
    return hex
  end

  # encode a hex string as base-58
  def self.base58_encode(h : String)
    # do a base58 mapping for the hash
    pub = BigInt.new h, 16
    adr = String.new
    while pub > 0
      pub, rem = pub.divmod 58
      adr += BASE_58[rem]
    end

    # replace leading zero bytes with 1
    i, s = 0, 2
    current_byte = h[i, s]
    while current_byte.to_i(16) === 0
      adr = "#{adr}1"
      i += s
      current_byte = h[i, s]
    end

    # reverse because we did the entire conversion backwards
    return adr.reverse
  end

  # get a character from the base-57 alphabet at position i
  def self.base57_char(i : Int32)
    i = i % 57
    return BASE_57[i]
  end

  # helper function to convert byte arrays to hex strings
  def self.bin_to_hex(b : Bytes)
    return b.hexstring
  end

  # helper function to convert hex strings to byte arrays
  def self.hex_to_bin(s : String)
    return s.hexbytes
  end
end
