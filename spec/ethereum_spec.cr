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

# tests for the Secp256k1::Ethereum module
describe Secp256k1::Ethereum do
  # tests a known ethereum address from a known private key
  it "can generate a valid ethereum address" do
    # private key and address taken from nick's edgeware tweet-storm
    # ref: https://twitter.com/nicksdjohnson/status/1146018827685126144
    adr = Secp256k1::Ethereum.address_from_private "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51"
    adr.should eq "0x2Ef1f605AF5d03874eE88773f41c1382ac71C239"
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
end
