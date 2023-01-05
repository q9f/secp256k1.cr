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

require "../spec_helper"

describe Secp256k1::Key do
  it "can create random key-pairs out of thin air" do
    10.times do
      rand = Key.new
      rand.private_hex.size.should eq 64
      rand.private_bytes.size.should eq 32
      rand.public_hex.size.should eq 130
      rand.public_bytes.size.should eq 65
    end
  end

  it "generates valid key-pairs from private key" do
    priv = Num.new "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"
    key = Key.new priv
    key.private_hex.should eq "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"
    key.private_bytes.should eq Bytes[160, 220, 101, 255, 202, 121, 152, 115, 203, 234, 10, 194, 116, 1, 91, 149, 38, 80, 93, 170, 174, 211, 133, 21, 84, 37, 247, 51, 119, 4, 136, 62]
    key.public_hex.should eq "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    key.public_bytes.should eq Bytes[4, 7, 145, 220, 112, 183, 90, 169, 149, 33, 50, 68, 173, 63, 72, 134, 215, 77, 97, 204, 211, 239, 101, 130, 67, 252, 173, 20, 201, 204, 238, 43, 10, 167, 98, 251, 198, 172, 9, 33, 184, 241, 112, 37, 187, 132, 88, 185, 39, 148, 174, 135, 161, 51, 137, 77, 112, 215, 153, 95, 192, 182, 181, 171, 144]
    priw = Num.new "55255657523dd1c65a77d3cb53fcd050bf7fc2c11bb0bb6edabdbd41ea51f641"
    kez = Key.new priw
    kez.private_hex.should eq "55255657523dd1c65a77d3cb53fcd050bf7fc2c11bb0bb6edabdbd41ea51f641"
    kez.private_bytes.should eq Bytes[85, 37, 86, 87, 82, 61, 209, 198, 90, 119, 211, 203, 83, 252, 208, 80, 191, 127, 194, 193, 27, 176, 187, 110, 218, 189, 189, 65, 234, 81, 246, 65]
    kez.public_hex.should eq "0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf"
    kez.public_bytes.should eq Bytes[4, 20, 252, 3, 184, 223, 135, 205, 123, 135, 41, 150, 129, 13, 184, 69, 141, 97, 218, 132, 72, 229, 49, 86, 156, 133, 23, 180, 105, 161, 25, 210, 103, 190, 86, 69, 104, 99, 9, 198, 230, 115, 109, 189, 147, 148, 7, 7, 204, 145, 67, 211, 207, 41, 241, 184, 119, 255, 52, 14, 44, 178, 210, 89, 207]
  end
end
