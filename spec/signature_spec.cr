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
      pub = Secp256k1::Util.public_key_from_private priv
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
    pub = Secp256k1::Util.public_key_from_private priv

    # Python:
    # > ******* Signature Generation *********
    # > r = 108450790312736419148091503336190989867379581793003243037811027177541631669413
    # > s = 93539716883975436131751270446270238300906572229893209404647676230869395610336
    r = BigInt.new "108450790312736419148091503336190989867379581793003243037811027177541631669413"
    s = BigInt.new "93539716883975436131751270446270238300906572229893209404647676230869395610336"
    sig = Secp256k1::ECDSASignature.new r, s, 0
    hash = BigInt.new "86032112319101611046176971828093669637772856272773459297323797145286374828050"

    # should be valid
    valid = Secp256k1::Signature.verify hash, sig, pub
    valid.should eq true
  end

  it "can handle r,s,v properly" do
    # ref https://github.com/q9f/eth.rb/blob/33b757c34c53200645444eb8f8797376ae304bb9/spec/eth/key_spec.rb#L69
    priv = BigInt.new "8e091dfb95a1b03cdd22890248c3f1b0f048186f2f3aa93257bc5271339eb306", 16
    key = Secp256k1::Keypair.new priv
    eth = Secp256k1::Ethereum::Account.new key
    eth.address.should eq "0x4cbeFF8966586874362ce4313D8f80cD404838a3"
    msg = "Lorem, Ipsum!"
    hash = Secp256k1::Hash.keccak256 msg
    hash.should eq "938ec6af3576cd774c0dd9c1b45ddc7980ae78a08be1f3f6826f71cb66611cef"
    hash = BigInt.new hash, 16
    sig = Secp256k1::Signature.sign hash, priv
    expected_r = BigInt.new "84a96dcf08f901a887cef46ecd8de8246012993b5b2a4a46ab3f8036fe57c53937", 16
    expected_s = BigInt.new "37106b3e04ec557e4614ebe87dc1678c3d49402009f4fd0a8d1b5e24a5577b392e", 16
    expected_v = BigInt.new "2e", 16
    sig.r.should eq expected_r
    sig.s.should eq expected_s
    sig.rec_id.should eq expected_v % 2
  end
end
