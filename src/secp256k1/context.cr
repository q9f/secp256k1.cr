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

class Secp256k1::Context
  def sign(key : Key, hash : Num)
    k = deterministic_k key.private_key, hash
    hash = hash.to_big
    priv = key.private_key.to_big
    point = Curve.mul G, k
    r = point.x.to_big % N.to_big
    k_inv = Curve.mod_inv k, N
    s = ((hash + r * priv) * k_inv.to_big) % N.to_big
    x_mag = point.x.to_big > N.to_big
    y_parity = (point.y.to_big % 2) == 0
    rec_id : Int8 = -1
    if y_parity && !x_mag
      rec_id = 0
    elsif !y_parity && !x_mag
      rec_id = 1
    elsif y_parity && x_mag
      rec_id = 2
    elsif !y_parity && x_mag
      rec_id = 3
    end
    r = Num.new r
    s = Num.new s
    v = Num.new BigInt.new rec_id
    Signature.new r, s, v
  end

  def verify(sig : Signature, hash : Num, publ : Point)
    s_inv = Curve.mod_inv sig.s, N
    p0 = Curve.mul G, (hash.to_big * s_inv.to_big) % N.to_big
    p1 = Curve.mul publ, (sig.r.to_big * s_inv.to_big) % N.to_big
    p = Curve.add p0, p1
    sig.r.to_big === p.x.to_big
  end

  private def deterministic_k(priv : Num, hash : Num, order = N)
    order_size = order.hex.size // 2
    v = Num.new Bytes.new order_size, 0x01
    k = Num.new Bytes.new order_size, 0x00
    io = IO::Memory.new v.bin.bytesize + 1 + priv.bin.bytesize + hash.bin.bytesize
    v.bin.each do |b|
      io.write_bytes UInt8.new b
    end
    io.write_bytes UInt8.new 0x00
    priv.bin.each do |b|
      io.write_bytes UInt8.new b
    end
    hash.bin.each do |b|
      io.write_bytes UInt8.new b
    end
    k = OpenSSL::HMAC.digest(:sha256, k.bin, io.to_slice)
    v = OpenSSL::HMAC.digest(:sha256, k, v.bin)
    io = IO::Memory.new v.bytesize + 1 + priv.bin.bytesize + hash.bin.bytesize
    v.each do |b|
      io.write_bytes UInt8.new b
    end
    io.write_bytes UInt8.new 0x00
    priv.bin.each do |b|
      io.write_bytes UInt8.new b
    end
    hash.bin.each do |b|
      io.write_bytes UInt8.new b
    end
    k = OpenSSL::HMAC.digest(:sha256, k, io.to_slice)
    v = OpenSSL::HMAC.digest(:sha256, k, v)
    while true
      t = IO::Memory.new.to_slice
      while t.size < order_size
        v = OpenSSL::HMAC.digest(:sha256, k, v)
        io = IO::Memory.new t.size + v.bytesize
        t.each do |b|
          io.write_bytes UInt8.new b
        end
        v.each do |b|
          io.write_bytes UInt8.new b
        end
        t = io.to_slice
      end
      secret = Num.new t
      if secret.dec < order.dec && secret.dec > 0
        return secret
      end
      io = IO::Memory.new v.bytesize + 1
      v.each do |b|
        io.write_bytes UInt8.new b
      end
      io.write_bytes UInt8.new 0x00
      k = OpenSSL::HMAC.digest(:sha256, k, io.to_slice)
      v = OpenSSL::HMAC.digest(:sha256, k, v)
    end
  end
end
