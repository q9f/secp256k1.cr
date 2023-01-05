# Copyright 2019-2023 Afri Schoedon @q9f
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

# Provides a collection of utilities for convenience, e.g., to bind
# relevant hashing algorithms, or to concatenate byte slices.
module Secp256k1::Util
  extend self

  # Operating a Keccak hash on a binary/number or string literal.
  #
  # Parameters:
  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed.
  # * `entropy` (`Int32`): the required entropy (default `256`).
  #
  # Returns a `Num` representing the Keccak hash.
  #
  # ```
  # Util.keccak(Num.new "0xdeadbeef").hex
  # # => "d4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1"
  #
  # Util.keccak("0xdeadbeef").hex
  # # => "4f440a001006a49f24a7de53c04eca3f79aef851ac58e460c9630d044277c8b0"
  # ```
  def keccak(data : Num | Bytes | String, entropy = 256) : Num
    keccak = Digest::Keccak3.new entropy
    if data.is_a? Num
      return Num.new keccak.update(data.to_bytes).hexdigest
    else
      return Num.new keccak.update(data).hexdigest
    end
  end

  # Operating a SHA3 hash on a binary/number or string literal.
  #
  # Parameters:
  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed.
  # * `entropy` (`Int32`): the required entropy (default `256`).
  #
  # Returns a `Num` representing the SHA3 hash.
  #
  # ```
  # Util.sha3(Num.new "0xdeadbeef").hex
  # # => "352b82608dad6c7ac3dd665bc2666e5d97803cb13f23a1109e2105e93f42c448"
  #
  # Util.sha3("0xdeadbeef").hex
  # # => "c12811e13ed75afe3e0945ef34e8a25b9d321a46e131c6463731de25a21b39eb"
  # ```
  def sha3(data : Num | Bytes | String, entropy = 256) : Num
    sha3 = Digest::SHA3.new entropy
    if data.is_a? Num
      return Num.new sha3.update(data.to_bytes).hexdigest
    else
      return Num.new sha3.update(data).hexdigest
    end
  end

  # Operating a SHA2-256 hash on a binary/number or string literal.
  #
  # Parameters:
  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed.
  #
  # Returns a `Num` representing the SHA2 hash.
  #
  # ```
  # Util.sha256(Num.new "0xdeadbeef").hex
  # # => "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953"
  #
  # Util.sha256("0xdeadbeef").hex
  # # => "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583"
  # ```
  def sha256(data : Num | Bytes | String) : Num
    sha2 = OpenSSL::Digest.new "SHA256"
    if data.is_a? Num
      return Num.new sha2.update(data.to_bytes).final.hexstring
    else
      return Num.new sha2.update(data).final.hexstring
    end
  end

  # Operating a RIPEMD-160 hash on a binary/number or string literal.
  #
  # Parameters:
  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed.
  #
  # Returns a `Num` representing the RIPEMD hash.
  #
  # ```
  # Util.ripemd160(Num.new "0xdeadbeef").hex
  # # => "226821c2f5423e11fe9af68bd285c249db2e4b5a"
  #
  # Util.ripemd160("0xdeadbeef").hex
  # # => "4caf817f14e84b564e47afd19966e5d123ee0183"
  # ```
  def ripemd160(data : Num | Bytes | String) : Num
    ripemd = OpenSSL::Digest.new "RIPEMD160"
    if data.is_a? Num
      return Num.new ripemd.update(data.to_bytes).final.hexstring
    else
      return Num.new ripemd.update(data).final.hexstring
    end
  end

  # Provides a deterministic secret based on private key and message hash
  # as defined in RFC-6979.
  #
  # Ref: [datatracker.ietf.org/doc/html/rfc6979](https://datatracker.ietf.org/doc/html/rfc6979)
  #
  # Parameters:
  # * `priv` (`Num`): the private key or secret number.
  # * `hash` (`Num`): the message hash or arbirtrary data hash.
  # * `order` (`Num`): the order of the curve over `G` (default `N`).
  #
  # Returns a deterministically random number of type `Num`.
  #
  # ```
  # priv = Num.new "3b74fcc0b0c419a00d2d9e88b15fbd99e03920138da22e2a00c327b88d24cf45"
  # hash = Util.sha256 "Henlo, Wordl"
  # Util.deterministic_k(priv, hash)
  # # => #<Secp256k1::Num:0x7f0eb8447280
  # #          @hex="b7ede9a5b5b328ac680be6765213c7b5b2920469bdaaf8070c1fb43cb5c440da",
  # #          @dec=83193606619515454920331057246310791124858301167609726617990890481932799590618,
  # #          @bin=Bytes[183, 237, 233, 165, 181, 179, 40, 172, 104, 11, 230, 118, 82, 19, 199, 181, 178, 146, 4, 105, 189, 170, 248, 7, 12, 31, 180, 60, 181, 196, 64, 218]>
  # ```
  def deterministic_k(priv : Num, hash : Num, order = N) : Num
    order_size = order.hex.size // 2
    v = Num.new Bytes.new order_size, 0x01
    k = Num.new Bytes.new order_size, 0x00
    concat = Util.concat_bytes v.bin, Bytes[0x00]
    concat = Util.concat_bytes concat, priv.bin
    concat = Util.concat_bytes concat, hash.bin
    k = OpenSSL::HMAC.digest(:sha256, k.bin, concat)
    v = OpenSSL::HMAC.digest(:sha256, k, v.bin)
    concat = Util.concat_bytes v, Bytes[0x00]
    concat = Util.concat_bytes concat, priv.bin
    concat = Util.concat_bytes concat, hash.bin
    k = OpenSSL::HMAC.digest(:sha256, k, concat)
    v = OpenSSL::HMAC.digest(:sha256, k, v)
    while true
      t = IO::Memory.new.to_slice
      while t.size < order_size
        v = OpenSSL::HMAC.digest(:sha256, k, v)
        t = Util.concat_bytes t, v
      end
      secret = Num.new t
      if secret.dec < order.dec && secret.dec > 0
        return secret
      end
      increment = Util.concat_bytes v, Bytes[0x00]
      k = OpenSSL::HMAC.digest(:sha256, k, increment)
      v = OpenSSL::HMAC.digest(:sha256, k, v)
    end
  end

  # Concatenates two byte slices in the order provided, i.e., `x|y`.
  #
  # Parameters:
  # * `x` (`Bytes`): a byte slice.
  # * `y` (`Bytes`): another byte slice.
  #
  # Returns a concatenated `Bytes` slice.
  #
  # ```
  # Util.concat_bytes Bytes[1, 2, 3], Bytes[9, 8, 7]
  # # => Bytes[1, 2, 3, 9, 8, 7]
  # ```
  def concat_bytes(x : Bytes, y : Bytes) : Bytes
    z = IO::Memory.new x.bytesize + y.bytesize
    x.each do |b|
      z.write_bytes UInt8.new b
    end
    y.each do |b|
      z.write_bytes UInt8.new b
    end
    return z.to_slice
  end
end
