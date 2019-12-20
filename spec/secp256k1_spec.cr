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

require "./spec_helper"

describe Secp256k1 do

  it "verifies constants" do
    # a couple of sanity check that ensures the parsed hex values represent the correct decimal numbers
    Secp256k1::EC_PARAM_PRIME.should eq BigInt.new "115792089237316195423570985008687907853269984665640564039457584007908834671663"
    Secp256k1::EC_BASE_G.should eq BigInt.new "286650441496909734516720688912544350032790572785058722254415355376215376009112"
    Secp256k1::EC_BASE_G_UNCOMPRESSED.should eq BigInt.new "60007469361611451595808076307103981948066675035911483428688400614800034609601690612527903279981446538331562636035761922566837056280671244382574348564747448"
    Secp256k1::EC_BASE_G_X.should eq BigInt.new "55066263022277343669578718895168534326250603453777594175500187360389116729240"
    Secp256k1::EC_BASE_G_Y.should eq BigInt.new "32670510020758816978083085130507043184471273380659243275938904335757337482424"
    Secp256k1::EC_FACTOR_A.should eq BigInt.new "0"
    Secp256k1::EC_FACTOR_B.should eq BigInt.new "7"
    Secp256k1::EC_ORDER_N.should eq BigInt.new "115792089237316195423570985008687907852837564279074904382605163141518161494337"
    Secp256k1::EC_COFACTOR_H.should eq BigInt.new "1"
  end

  it "pads 32 byte hex strings with leading zeros" do
    # maximum padding for 32 zero bytes
    a = Secp256k1.to_padded_hex_32 Secp256k1::EC_FACTOR_A
    a.should eq "0000000000000000000000000000000000000000000000000000000000000000"
    b = Secp256k1.to_padded_hex_32 Secp256k1::EC_FACTOR_B
    b.should eq "0000000000000000000000000000000000000000000000000000000000000007"
    
    # no padding required for the max possible value
    n = Secp256k1.to_padded_hex_32 Secp256k1::EC_ORDER_N
    n.should eq Secp256k1::EC_ORDER_N.to_s 16
  end

  it "computes modular multiplicative inverse of a" do
    # using 32 random bytes for a
    a = BigInt.new "5d5c75e7a6cd4b7fd7fbbf3fe78d97695b59c02a6c1c6a25d052fc736d9f07e6", 16
    a.should eq BigInt.new "42228458597839933933186074561522669313020758244811500203476962190108286453734"
    
    # passing them to ec mod_inv
    i = Secp256k1.ec_mod_inv a
    
    # python: `print modinv(42228458597839933933186074561522669313020758244811500203476962190108286453734)`
    # > 22252956326688633405392632421204971006307850186723512069020209708471515620360
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L16
    i.should eq BigInt.new "22252956326688633405392632421204971006307850186723512069020209708471515620360"
  end

  it "computes ec addition of p and q" do
    # using the generator point
    p = Secp256k1::EC_Point.new Secp256k1::EC_BASE_G_X, Secp256k1::EC_BASE_G_Y
    
    # adding the generator point to generator point
    r = Secp256k1.ec_add p, p

    # python: `print ECadd(GPoint, GPoint)`
    # > (5659563192761508084413547218350839200768777758085375688457209287130601213183L, 83121579216557378445487899878180864668798711284981320763518679672151497189239L)
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L25
    r.x.should eq BigInt.new "5659563192761508084413547218350839200768777758085375688457209287130601213183"
    r.y.should eq BigInt.new "83121579216557378445487899878180864668798711284981320763518679672151497189239"
    
    # adding the generator point to a reverse generator point
    q = Secp256k1::EC_Point.new Secp256k1::EC_BASE_G_Y, Secp256k1::EC_BASE_G_X
    s = Secp256k1.ec_add p, q

    # python: `print ECadd((Gx, Gy), (Gy, Gx))`
    # > (28055316194280034775909180983012330342548107831203726588018492311762380460000L, 56110632388560069551818361966024660685096215662407453176036984623524760919999L)
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L25
    s.x.should eq BigInt.new "28055316194280034775909180983012330342548107831203726588018492311762380460000"
    s.y.should eq BigInt.new "56110632388560069551818361966024660685096215662407453176036984623524760919999"
  end

  it "computes ec doubling of p" do
    # using the generator point
    p = Secp256k1::EC_Point.new Secp256k1::EC_BASE_G_X, Secp256k1::EC_BASE_G_Y

    # doubling the generator point
    r = Secp256k1.ec_double p

    # python: `print ECdouble(GPoint)`
    # > (89565891926547004231252920425935692360644145829622209833684329913297188986597L, 12158399299693830322967808612713398636155367887041628176798871954788371653930L)
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L31
    r.x.should eq BigInt.new "89565891926547004231252920425935692360644145829622209833684329913297188986597"
    r.y.should eq BigInt.new "12158399299693830322967808612713398636155367887041628176798871954788371653930"
  end

  it "generates valid public key" do
    # taking the private key from the python blackboard 101
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L14
    priv = BigInt.new "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e", 16
    priv.should eq BigInt.new "72759466100064397073952777052424474334519735946222029294952053344302920927294"
    p = Secp256k1.public_key_from_private priv

    # python: print EccMultiply(GPoint, privKey)
    # > (3423904187495496827825042940737875085827330420143621346629173781207857376010L, 75711134420273723792089656449854389054866833762486990555172221523628676983696L)
    p.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    p.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"

    # > the uncompressed public key (hex):
    # > 040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90
    uncm = Secp256k1.public_key_uncompressed_prefix p
    uncm.should eq "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"

    # > the official public key - compressed:
    # > 020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a
    publ = Secp256k1.public_key_compressed_prefix p
    publ.should eq "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
  end
end
