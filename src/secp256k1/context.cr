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

# Provides a `Secp256k1` context to allow signing arbitrary data,
# recovering public keys, and verifying signatures.
#
# ```
# ctx = Context.new
# # => #<Secp256k1::Context:0x7fc855a23e60>
# ```
class Secp256k1::Context
  # Signs a message hash or any other arbitrary data with a given keypair.
  #
  # Parameters:
  # * `key` (`Key`): the keypair containing a secret to sign the data.
  # * `hash` (`Num`): the message or arbirtrary data hash.
  #
  # ```
  # ctx = Context.new
  # key = Key.new Num.new "1f0c122d41ff536b19bfd83537c0dfc290e45cd3c375a43237c8b8fff7ac8af7"
  # hash = Util.sha256 "Henlo, Wordl"
  # sig = ctx.sign key, hash
  # # => #<Secp256k1::Signature:0x7f5332e1d9c0
  # #          @r=#<Secp256k1::Num:0x7f5332decac0
  # #              @hex="c4079db44240b7afe94985c69fc89602e33629fd9b8623d711c30ce6378b33df",
  # #              @dec=88666774685717741514025410921892109286073075687452443491001272268566542627807,
  # #              @bin=Bytes[196, 7, 157, 180, 66, 64, 183, 175, 233, 73, 133, 198, 159, 200, 150, 2, 227, 54, 41, 253, 155, 134, 35, 215, 17, 195, 12, 230, 55, 139, 51, 223]>,
  # #          @s=#<Secp256k1::Num:0x7f5332deca80
  # #              @hex="6842c1b63c94bdb8e4f5ae88fb65f7a98b77b197c8323004fb47ef57fab29053",
  # #              @dec=47158485109070227797431103290229472044663017260590156038384319099500326195283,
  # #              @bin=Bytes[104, 66, 193, 182, 60, 148, 189, 184, 228, 245, 174, 136, 251, 101, 247, 169, 139, 119, 177, 151, 200, 50, 48, 4, 251, 71, 239, 87, 250, 178, 144, 83]>,
  # #          @v=#<Secp256k1::Num:0x7f5332deca40
  # #              @hex="00",
  # #              @dec=0,
  # #              @bin=Bytes[0]>>
  # ```
  def sign(key : Key, hash : Num)
    k = Util.deterministic_k key.private_key, hash
    hash = hash.to_big
    priv = key.private_key.to_big
    point = Curve.mul G, k
    r = point.x.to_big % N.to_big
    k_inv = Curve.mod_inv k, N
    s = ((hash + r * priv) * k_inv.to_big) % N.to_big
    x_mag = point.x.to_big > N.to_big
    y_parity = (point.y.to_big % 2) == 0
    rec_id : Int8 = -1
    if !y_parity && x_mag
      rec_id = 3
    elsif y_parity && x_mag
      rec_id = 2
    elsif !y_parity && !x_mag
      rec_id = 1
    else
      rec_id = 0
    end
    r = Num.new r
    s = Num.new s
    v = Num.new BigInt.new rec_id
    Signature.new r, s, v
  end

  # Verifies that a given signature for a given message hash matches
  # the provided public key.
  #
  # Parameters:
  # * `sig` (`Signature`): the signature to be verified.
  # * `hash` (`Num`): the message or arbirtrary data hash.
  # * `publ` (`Point`): the public key to match.
  #
  # ```
  # ctx = Context.new
  # r = Num.new "c4079db44240b7afe94985c69fc89602e33629fd9b8623d711c30ce6378b33df"
  # s = Num.new "6842c1b63c94bdb8e4f5ae88fb65f7a98b77b197c8323004fb47ef57fab29053"
  # v = Num.new "00"
  # sig = Signature.new r, s, v
  # hash = Util.sha256 "Henlo, Wordl"
  # publ = Point.new "0416008a369439f1a8a75cf974860bed5b10180518d6b1dd3ac847f423fd375d6aa29474394f0cd79d2ea543507d069e97339284f01bdbfd27392daec0ec553816"
  # ctx.verify sig, hash, publ
  # # => true
  # ```
  def verify(sig : Signature, hash : Num, publ : Point)
    s_inv = Curve.mod_inv sig.s, N
    p0 = Curve.mul G, (hash.to_big * s_inv.to_big) % N.to_big
    p1 = Curve.mul publ, (sig.r.to_big * s_inv.to_big) % N.to_big
    p = Curve.add p0, p1
    sig.r.to_big === p.x.to_big
  end
end
