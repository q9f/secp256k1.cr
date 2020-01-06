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

# tests for the Secp256k1::Core module
describe Secp256k1::Core do
  # tests the ec mod_inv against the referenced python implementation
  it "computes modular multiplicative inverse of a" do
    # using 32 random bytes for a
    a = BigInt.new "5d5c75e7a6cd4b7fd7fbbf3fe78d97695b59c02a6c1c6a25d052fc736d9f07e6", 16
    a.should eq BigInt.new "42228458597839933933186074561522669313020758244811500203476962190108286453734"

    # passing them to ec mod_inv
    i = Secp256k1::Core.ec_mod_inv a

    # python: `print modinv(42228458597839933933186074561522669313020758244811500203476962190108286453734)`
    # > 22252956326688633405392632421204971006307850186723512069020209708471515620360
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L16
    i.should eq BigInt.new "22252956326688633405392632421204971006307850186723512069020209708471515620360"
  end

  # tests the ec add against the referenced python implementation
  it "computes ec addition of p and q" do
    # adding the generator point to generator point
    r = Secp256k1::Core.ec_add Secp256k1::EC_BASE_G, Secp256k1::EC_BASE_G

    # python: `print ECadd(GPoint, GPoint)`
    # > (5659563192761508084413547218350839200768777758085375688457209287130601213183L, 83121579216557378445487899878180864668798711284981320763518679672151497189239L)
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L25
    r.x.should eq BigInt.new "5659563192761508084413547218350839200768777758085375688457209287130601213183"
    r.y.should eq BigInt.new "83121579216557378445487899878180864668798711284981320763518679672151497189239"

    # adding the generator point to a reverse generator point x, y = y, x
    q = Secp256k1::EC_Point.new Secp256k1::EC_BASE_G_Y, Secp256k1::EC_BASE_G_X
    s = Secp256k1::Core.ec_add Secp256k1::EC_BASE_G, q

    # python: `print ECadd((Gx, Gy), (Gy, Gx))`
    # > (28055316194280034775909180983012330342548107831203726588018492311762380460000L, 56110632388560069551818361966024660685096215662407453176036984623524760919999L)
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L25
    s.x.should eq BigInt.new "28055316194280034775909180983012330342548107831203726588018492311762380460000"
    s.y.should eq BigInt.new "56110632388560069551818361966024660685096215662407453176036984623524760919999"
  end

  # tests the ec double against the referenced python implementation
  it "computes ec doubling of p" do
    # doubling the generator point
    r = Secp256k1::Core.ec_double Secp256k1::EC_BASE_G

    # python: `print ECdouble(GPoint)`
    # > (89565891926547004231252920425935692360644145829622209833684329913297188986597L, 12158399299693830322967808612713398636155367887041628176798871954788371653930L)
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L31
    r.x.should eq BigInt.new "89565891926547004231252920425935692360644145829622209833684329913297188986597"
    r.y.should eq BigInt.new "12158399299693830322967808612713398636155367887041628176798871954788371653930"
  end
end
