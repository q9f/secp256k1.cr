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

# tests for the Secp256k1::Utils module
describe Secp256k1::Utils do
  # tests the correct pedding for hex keys to ensure they are always 32 bytes in size
  it "pads 32 byte hex strings with leading zeros" do
    # maximum padding for 32 zero bytes
    a = Secp256k1::Utils.to_padded_hex_32 Secp256k1::EC_FACTOR_A
    a.should eq "0000000000000000000000000000000000000000000000000000000000000000"

    # high padding for 0x7
    b = Secp256k1::Utils.to_padded_hex_32 Secp256k1::EC_FACTOR_B
    b.should eq "0000000000000000000000000000000000000000000000000000000000000007"

    # no padding required for the max possible value
    n = Secp256k1::Utils.to_padded_hex_32 Secp256k1::EC_ORDER_N
    n.should eq Secp256k1::Utils.to_padded_hex_32 Secp256k1::EC_ORDER_N
  end

  # tests the ec mul operation to retrieve a valid public key from a known private key
  it "generates valid public key" do
    # taking the private key from the python blackboard 101
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L14
    priv = BigInt.new "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e", 16
    priv.should eq BigInt.new "72759466100064397073952777052424474334519735946222029294952053344302920927294"
    p = Secp256k1::Utils.public_key_from_private priv

    # python: print EccMultiply(GPoint, privKey)
    # > (3423904187495496827825042940737875085827330420143621346629173781207857376010L, 75711134420273723792089656449854389054866833762486990555172221523628676983696L)
    p.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    p.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"

    # the uncompressed public key (hex):
    # > 040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90
    uncm = Secp256k1::Utils.public_key_uncompressed_prefix p
    uncm.should eq "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"

    # the official public key - compressed:
    # > 020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a
    publ = Secp256k1::Utils.public_key_compressed_prefix p
    publ.should eq "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"

    # taking the private key from bitcointalk
    # ref: https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689
    priv = BigInt.new "55255657523dd1c65a77d3cb53fcd050bf7fc2c11bb0bb6edabdbd41ea51f641", 16
    priv.should eq BigInt.new "38512561375336666218975019341699212961293425532484539208601808874461264475713"
    p = Secp256k1::Utils.public_key_from_private priv

    # > compressed_key = '0314fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267'
    publ = Secp256k1::Utils.public_key_compressed_prefix p
    publ.should eq "0314fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267"

    # > uncompressed_key = '04{:x}{:x}'.format(x, y)
    # > 0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf
    uncm = Secp256k1::Utils.public_key_uncompressed_prefix p
    uncm.should eq "0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf"
  end

  # makes sure no ec multiplication is done with invalid private keys
  it "does not allow invalid private keys" do
    key_too_low = BigInt.new 0
    key_too_high = BigInt.new "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16

    # zero or greater field size should raise an exception
    expect_raises Exception, "invalid private key: outside of ec field size." do
      Secp256k1::Utils.public_key_from_private key_too_low
      Secp256k1::Utils.public_key_from_private key_too_high
    end

    # some securely random generated keys should pass
    iter = 0
    while iter < 10
      key_random = Secp256k1::Utils.new_private_key
      Secp256k1::Utils.public_key_from_private key_random
      iter += 1
    end
  end

  # should be able to recover ec points from compressed public key strings
  it "restores public ec point from public key strings" do
    # uncompressed keys can be restored with or without prefix
    uncompressed_with_prefix = "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    uncompressed_without_prefix = "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    p = Secp256k1::Utils.restore_public_key uncompressed_with_prefix
    q = Secp256k1::Utils.restore_public_key uncompressed_without_prefix

    # testing against the same key from the python blackboard 101
    p.not_nil!.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    p.not_nil!.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"
    q.not_nil!.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    q.not_nil!.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"

    # compressed keys can only be restored with prefix
    compressed_with_prefix = "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    r = Secp256k1::Utils.restore_public_key compressed_with_prefix

    # testing against the same key from the python blackboard 101
    r.not_nil!.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    r.not_nil!.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"

    # compressed without prefix should raise an exception
    compressed_without_prefix = "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    expect_raises Exception, "unknown public key format (invalid key size: 64)" do
      Secp256k1::Utils.restore_public_key compressed_without_prefix
    end

    # invalid key (cut off) should raise an exception
    uncompressed_invalid = "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb"
    expect_raises Exception, "unknown public key format (invalid key size: 90)" do
      Secp256k1::Utils.restore_public_key uncompressed_invalid
    end

    # invalid key (invalid prefix) should raise an exception
    compressed_invalid = "080791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    expect_raises Exception, "invalid prefix for compressed public key: 08" do
      Secp256k1::Utils.restore_public_key compressed_invalid
    end
  end
end

# tests for the Secp256k1::Signature module
describe Secp256k1::Signature do # signs and verifies a message using the private key from the python blackboard 101
  # ref: https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py#L11
  it "can sign a message" do
    priv = BigInt.new "75263518707598184987916378021939673586055614731957507592904438851787542395619"
    msg = "Hello, World!"
    sig = Secp256k1::Signature.sign msg, priv
    iter = 0

    # generate 10 random signatures for the same message and key
    while iter < 10
      sig = Secp256k1::Signature.sign msg, priv
      pub = Secp256k1::Utils.public_key_from_private priv
      valid = Secp256k1::Signature.verify msg, sig, pub
      valid.should eq true
      iter += 1
    end
  end

  # verifies the hash from the python blackboard 101
  # ref: https://www.youtube.com/watch?v=U2bw_N6kQL8
  # ref: https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py#L13
  it "can verify a public signature" do
    priv = BigInt.new "75263518707598184987916378021939673586055614731957507592904438851787542395619"
    pub = Secp256k1::Utils.public_key_from_private priv

    # Python:
    # > ******* Signature Generation *********
    # > r = 108450790312736419148091503336190989867379581793003243037811027177541631669413
    # > s = 93539716883975436131751270446270238300906572229893209404647676230869395610336
    r = BigInt.new "108450790312736419148091503336190989867379581793003243037811027177541631669413"
    s = BigInt.new "93539716883975436131751270446270238300906572229893209404647676230869395610336"
    sig = Secp256k1::ECDSA_Signature.new r, s
    hash = BigInt.new "86032112319101611046176971828093669637772856272773459297323797145286374828050"

    # should be valid
    valid = Secp256k1::Signature.verify_hash hash, sig, pub
    valid.should eq true
  end
end
