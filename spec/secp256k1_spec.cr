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

require "./spec_helper"

# tests for the Secp256k1 module
describe Secp256k1 do
  # a couple of sanity check that ensures the parsed hex values represent the correct decimal numbers
  it "verifies constants" do
    Secp256k1::EC_PARAM_PRIME.should eq BigInt.new "115792089237316195423570985008687907853269984665640564039457584007908834671663"
    Secp256k1::EC_BASE_G_COMPRESSED.should eq BigInt.new "286650441496909734516720688912544350032790572785058722254415355376215376009112"
    Secp256k1::EC_BASE_G_UNCOMPRESSED.should eq BigInt.new "60007469361611451595808076307103981948066675035911483428688400614800034609601690612527903279981446538331562636035761922566837056280671244382574348564747448"
    Secp256k1::EC_BASE_G_X.should eq BigInt.new "55066263022277343669578718895168534326250603453777594175500187360389116729240"
    Secp256k1::EC_BASE_G_Y.should eq BigInt.new "32670510020758816978083085130507043184471273380659243275938904335757337482424"
    Secp256k1::EC_FACTOR_A.should eq BigInt.new "0"
    Secp256k1::EC_FACTOR_B.should eq BigInt.new "7"
    Secp256k1::EC_ORDER_N.should eq BigInt.new "115792089237316195423570985008687907852837564279074904382605163141518161494337"
    Secp256k1::EC_COFACTOR_H.should eq BigInt.new "1"
  end
end
