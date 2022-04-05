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

module Secp256k1::Util
  extend self

  def keccak(data : Num | String, entropy = 256)
    keccak = Digest::Keccak3.new entropy
    if data.is_a? String
      return Num.new keccak.update(data).hexdigest
    else
      return Num.new keccak.update(data.to_bytes).hexdigest
    end
  end

  def sha3(data : Num | String, entropy = 256)
    sha3 = Digest::SHA3.new entropy
    if data.is_a? String
      return Num.new sha3.update(data).hexdigest
    else
      return Num.new sha3.update(data.to_bytes).hexdigest
    end
  end

  def sha256(data : Num | String)
    sha2 = OpenSSL::Digest.new "SHA256"
    if data.is_a? String
      return Num.new sha2.update(data).final.hexstring
    else
      return Num.new sha2.update(data.to_bytes).final.hexstring
    end
  end

  def ripemd160(data : Num | String)
    ripemd = OpenSSL::Digest.new "RIPEMD160"
    if data.is_a? String
      return Num.new ripemd.update(data).final.hexstring
    else
      return Num.new ripemd.update(data.to_bytes).final.hexstring
    end
  end

  def concat_bytes(x : Bytes, y : Bytes)
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
