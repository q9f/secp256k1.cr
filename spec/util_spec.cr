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

# tests for the Secp256k1::Util module
describe Secp256k1::Util do
  # tests the correct pedding for hex keys to ensure they are always 32 bytes in size
  it "pads 32 byte hex strings with leading zeros" do
    # maximum padding for 32 zero bytes
    a = Secp256k1::Util.to_padded_hex_32 Secp256k1::EC_FACTOR_A
    a.should eq "0000000000000000000000000000000000000000000000000000000000000000"

    # high padding for 0x7
    b = Secp256k1::Util.to_padded_hex_32 Secp256k1::EC_FACTOR_B
    b.should eq "0000000000000000000000000000000000000000000000000000000000000007"

    # no padding required for the max possible value
    n = Secp256k1::Util.to_padded_hex_32 Secp256k1::EC_ORDER_N
    n.should eq Secp256k1::Util.to_padded_hex_32 Secp256k1::EC_ORDER_N
  end

  # tests the ec mul operation to retrieve a valid public key from a known private key
  it "generates valid public key" do
    # taking the private key from the python blackboard 101
    # ref: https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py#L14
    priv = BigInt.new "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e", 16
    priv.should eq BigInt.new "72759466100064397073952777052424474334519735946222029294952053344302920927294"
    p = Secp256k1::Util.public_key_from_private priv

    # python: print EccMultiply(GPoint, privKey)
    # > (3423904187495496827825042940737875085827330420143621346629173781207857376010L, 75711134420273723792089656449854389054866833762486990555172221523628676983696L)
    p.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    p.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"

    # the uncompressed public key (hex):
    # > 040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90
    uncm = Secp256k1::Util.public_key_uncompressed_prefix p
    uncm.should eq "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"

    # the official public key - compressed:
    # > 020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a
    publ = Secp256k1::Util.public_key_compressed_prefix p
    publ.should eq "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"

    # taking the private key from bitcointalk
    # ref: https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689
    priv = BigInt.new "55255657523dd1c65a77d3cb53fcd050bf7fc2c11bb0bb6edabdbd41ea51f641", 16
    priv.should eq BigInt.new "38512561375336666218975019341699212961293425532484539208601808874461264475713"
    p = Secp256k1::Util.public_key_from_private priv

    # > compressed_key = '0314fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267'
    publ = Secp256k1::Util.public_key_compressed_prefix p
    publ.should eq "0314fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267"

    # > uncompressed_key = '04{:x}{:x}'.format(x, y)
    # > 0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf
    uncm = Secp256k1::Util.public_key_uncompressed_prefix p
    uncm.should eq "0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf"
  end

  # makes sure no ec multiplication is done with invalid private keys
  it "does not allow invalid private keys" do
    key_too_low = BigInt.new 0
    key_too_high = BigInt.new "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16

    # zero or greater field size should raise an exception
    expect_raises Exception, "invalid private key: outside of ec field size." do
      Secp256k1::Util.public_key_from_private key_too_low
      Secp256k1::Util.public_key_from_private key_too_high
    end

    # some securely random generated keys should pass
    iter = 0
    while iter < 10
      key_random = Secp256k1::Util.new_private_key
      Secp256k1::Util.public_key_from_private key_random
      iter += 1
    end
  end

  # should be able to recover ec points from compressed public key strings
  it "restores public ec point from public key strings" do
    # uncompressed keys can be restored with or without prefix
    uncompressed_with_prefix = "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    uncompressed_without_prefix = "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    p = Secp256k1::Util.restore_public_key uncompressed_with_prefix
    q = Secp256k1::Util.restore_public_key uncompressed_without_prefix

    # testing against the same key from the python blackboard 101
    p.not_nil!.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    p.not_nil!.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"
    q.not_nil!.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    q.not_nil!.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"

    # compressed keys can only be restored with prefix
    compressed_with_prefix = "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    r = Secp256k1::Util.restore_public_key compressed_with_prefix

    # testing against the same key from the python blackboard 101
    r.not_nil!.x.should eq BigInt.new "3423904187495496827825042940737875085827330420143621346629173781207857376010"
    r.not_nil!.y.should eq BigInt.new "75711134420273723792089656449854389054866833762486990555172221523628676983696"

    # compressed without prefix should raise an exception
    compressed_without_prefix = "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    expect_raises Exception, "unknown public key format (invalid key size: 64)" do
      Secp256k1::Util.restore_public_key compressed_without_prefix
    end

    # invalid key (cut off) should raise an exception
    uncompressed_invalid = "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb"
    expect_raises Exception, "unknown public key format (invalid key size: 90)" do
      Secp256k1::Util.restore_public_key uncompressed_invalid
    end

    # invalid key (invalid prefix) should raise an exception
    compressed_invalid = "080791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    expect_raises Exception, "invalid prefix for compressed public key: 08" do
      Secp256k1::Util.restore_public_key compressed_invalid
    end
  end
end
