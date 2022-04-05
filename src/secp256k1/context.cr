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

  private def deterministic_k(priv : Num, hash : Num)
    determined = (hash.to_big + priv.to_big) % N.to_big
    Util.sha256 Num.new determined
  end
end
