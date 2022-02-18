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

# tests for the Secp256k1::Ethereum module
describe Secp256k1::Ethereum do
  # tests a known ethereum address from a known private key
  it "can generate a valid ethereum address" do
    # private key and address taken from nick's edgeware tweet-storm
    # ref: https://twitter.com/nicksdjohnson/status/1146018827685126144
    priv = BigInt.new "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51", 16
    key = Secp256k1::Keypair.new priv
    eth = Secp256k1::Ethereum::Account.new key
    eth.address.should eq "0x2Ef1f605AF5d03874eE88773f41c1382ac71C239"
  end

  # tests a known ethereum key to be used for an enode address
  it "can generate a valid enode address" do
    # private key and address taken from nick's edgeware tweet-storm
    # ref: https://twitter.com/nicksdjohnson/status/1146018827685126144
    priv = BigInt.new "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51", 16
    key = Secp256k1::Keypair.new priv
    enode = Secp256k1::Ethereum::Enode.new key, "127.0.0.1", 30303
    enode.to_s.should eq "enode://bf0cf8c934bd3c57e962fdf2a47e99d6136b047f987ee2e0cb03110cafd92afc981974428f8162d3f8fce2f58d4e56341478e87d092aeb3a0edf8af97d638d04@127.0.0.1:30303"
    enode = Secp256k1::Ethereum::Enode.new key, "192.168.1.37", 50000
    enode.to_s.should eq "enode://bf0cf8c934bd3c57e962fdf2a47e99d6136b047f987ee2e0cb03110cafd92afc981974428f8162d3f8fce2f58d4e56341478e87d092aeb3a0edf8af97d638d04@192.168.1.37:50000"
  end

  # implements the eip-55 test cases
  # ref: https://eips.ethereum.org/EIPS/eip-55
  it "passes eip-55 ethereum address mix-case checksums" do
    chk_0 = Secp256k1::Ethereum.address_checksum "0x52908400098527886e0f7030069857d2e4169ee7"
    chk_1 = Secp256k1::Ethereum.address_checksum "8617e340b3d01fa5f11f306f4090fd50e238070d"
    chk_2 = Secp256k1::Ethereum.address_checksum "0xDE709F2102306220921060314715629080E2FB77"
    chk_3 = Secp256k1::Ethereum.address_checksum "27B1FDB04752BBC536007A920D24ACB045561C26"
    chk_4 = Secp256k1::Ethereum.address_checksum "0x5AaEB6053f3e94c9B9a09F33669435e7eF1bEaED"
    chk_5 = Secp256k1::Ethereum.address_checksum "0xFb6916095CA1DF60Bb79cE92Ce3eA74C37C5D359"
    chk_6 = Secp256k1::Ethereum.address_checksum "DBf03b407C01e7Cd3cbEA99509D93F8dddc8c6fb"
    chk_7 = Secp256k1::Ethereum.address_checksum "d1220a0CF47C7b9bE7a2e6ba89f429762E7B9AdB"
    chk_0.should eq "0x52908400098527886E0F7030069857D2E4169EE7"
    chk_1.should eq "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
    chk_2.should eq "0xde709f2102306220921060314715629080e2fb77"
    chk_3.should eq "0x27b1fdb04752bbc536007a920d24acb045561c26"
    chk_4.should eq "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    chk_5.should eq "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    chk_6.should eq "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
    chk_7.should eq "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"

    # passing a private key should raise
    expect_raises Exception, "malformed ethereum address (invalid size: 64)" do
      Secp256k1::Ethereum.address_checksum "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51"
    end
  end

  it "can handle r,s,v properly" do
    # ref https://github.com/q9f/eth.rb/blob/33b757c34c53200645444eb8f8797376ae304bb9/spec/eth/key_spec.rb#L69
    priv = BigInt.new "8e091dfb95a1b03cdd22890248c3f1b0f048186f2f3aa93257bc5271339eb306", 16
    key = Secp256k1::Keypair.new priv
    eth = Secp256k1::Ethereum::Account.new key
    eth.address.should eq "0x4cbeFF8966586874362ce4313D8f80cD404838a3"
    msg = "Lorem, Ipsum!"
    sig = eth.personal_sign msg, priv, 1
    expected_r = BigInt.new "83456641650431978396409163408327293713417920469844290225578553689609335539463"
    expected_s = BigInt.new "105121634897190108012533348460722927364827186380080232150571278011929803075236"
    expected_v = 37
    sig.r.should eq expected_r
    sig.s.should eq expected_s
    sig.v.should eq expected_v
    sig.to_s.should eq "b882c90541469501e20712af000b56976bb8acdc6d49c9ca15a7a5f13cad0707e868bca34f4bcb111c88b43f2251064dfc9bced7e3e337312d53d114c507aea425"
    prefixed = "\x19Ethereum Signed Message:\n#{msg.size}#{msg}"
    hash = BigInt.new Secp256k1::Hash.keccak256(prefixed), 16
    valid = Secp256k1::Signature.verify hash, sig, key.public_key
    valid.should eq true
  end
end
