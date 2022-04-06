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

# Provides an ECDSA Signature containing the random point `r`, the
# signature proof `s`, and the recovery id or `v` value.
#
# Properties:
# * `r` (`Num`): the `x` coordinate of a random point `R` on the curve.
# * `s` (`Num`): the signature proof of a message.
# * `v` (`Num`): the recovery id or `v` value.
class Secp256k1::Signature
  # The `x` coordinate of a random point `R` on the curve.
  getter r : Num

  # The signature proof of a message.
  getter s : Num

  # The recovery id or `v` value.
  getter v : Num

  # Provides an ECDSA Signature containing the random point `r`, the
  # signature proof `s`, and the recovery id or `v` value.
  #
  # Parameters:
  # * `r` (`Num`): the `x` coordinate of a random point `R` on the curve.
  # * `s` (`Num`): the signature proof of a message.
  # * `v` (`Num`): the recovery id or `v` value.
  #
  # ```
  # r = Num.new "efc4f8d8bfc778463e4d4916d88bf3f057e6dc96cb2adc26dfb91959c4bef4a5"
  # s = Num.new "cecd9a83fefafcb3cf99fde0c340bbe2fed9cdd0d25b53f4e08254acefb69ae0"
  # v = Num.new "00"
  # Signature.new r, s, v
  # # => #<Secp256k1::Signature:0x7f67a3f97e40
  # #          @r=#<Secp256k1::Num:0x7f67a3f91480
  # #              @hex="efc4f8d8bfc778463e4d4916d88bf3f057e6dc96cb2adc26dfb91959c4bef4a5",
  # #              @dec=108450790312736419148091503336190989867379581793003243037811027177541631669413,
  # #              @bin=Bytes[239, 196, 248, 216, 191, 199, 120, 70, 62, 77, 73, 22, 216, 139, 243, 240, 87, 230, 220, 150, 203, 42, 220, 38, 223, 185, 25, 89, 196, 190, 244, 165]>,
  # #          @s=#<Secp256k1::Num:0x7f67a3f913c0
  # #              @hex="cecd9a83fefafcb3cf99fde0c340bbe2fed9cdd0d25b53f4e08254acefb69ae0",
  # #              @dec=93539716883975436131751270446270238300906572229893209404647676230869395610336,
  # #              @bin=Bytes[206, 205, 154, 131, 254, 250, 252, 179, 207, 153, 253, 224, 195, 64, 187, 226, 254, 217, 205, 208, 210, 91, 83, 244, 224, 130, 84, 172, 239, 182, 154, 224]>,
  # #          @v=#<Secp256k1::Num:0x7f67a3f91380
  # #              @hex="00",
  # #              @dec=0,
  # #              @bin=Bytes[0]>>
  # ```
  def initialize(r : Num, s : Num, v : Num)
    @r = r
    @s = s
    @v = v
  end

  # Returns a compact `String` containing the concatenated signature
  # in the form `r|s|v`.
  #
  # ```
  # r = Num.new "efc4f8d8bfc778463e4d4916d88bf3f057e6dc96cb2adc26dfb91959c4bef4a5"
  # s = Num.new "cecd9a83fefafcb3cf99fde0c340bbe2fed9cdd0d25b53f4e08254acefb69ae0"
  # v = Num.new "00"
  # Signature.new(r, s, v).compact
  # # => "efc4f8d8bfc778463e4d4916d88bf3f057e6dc96cb2adc26dfb91959c4bef4a5cecd9a83fefafcb3cf99fde0c340bbe2fed9cdd0d25b53f4e08254acefb69ae000"
  # ```
  def compact : String
    "#{r.to_zpadded_hex}#{s.to_zpadded_hex}#{v.to_hex}"
  end
end
