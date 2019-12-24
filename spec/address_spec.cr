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

# tests for the Crypto module
describe Crypto do
  it "can hash sha3-256 correctly" do
    # sha3-256 hash taken from the crystal-sha3 readme
    # ref: https://github.com/OscarBarrett/crystal-sha3/blob/7b6f6e02196b106ecf0be01da207dbf1e269009b/README.md
    sha3 = Crypto.sha3_string "abc123"
    sha3.should eq "f58fa3df820114f56e1544354379820cff464c9c41cb3ca0ad0b0843c9bb67ee"

    # hash the previous hash again as bytes array instead of a string input
    sha3 = Crypto.sha3 sha3
    sha3.should eq "fb6123314cfb14af7a38a1d6a86a78598a204d7423e25810dad1ec8a8ef5094c"
  end

  it "can hash keccak-256 correctly" do
    # keccak-256 hash taken from the crystal-sha3 readme
    # ref: https://github.com/OscarBarrett/crystal-sha3/blob/7b6f6e02196b106ecf0be01da207dbf1e269009b/README.md
    keccak = Crypto.keccak256_string "abc123"
    keccak.should eq "719accc61a9cc126830e5906f9d672d06eab6f8597287095a2c55a8b775e7016"

    # hash the previous hash again as bytes array instead of a string input
    keccak = Crypto.keccak256 keccak
    keccak.should eq "438a3f652b00153f899189d56c7a70d0b3906b5a6ca4f585de47ac159b630bc0"
  end

  it "can hash sha-256 correctly" do
    # sha-256 hashes taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    sha2 = Crypto.sha256 "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    sha2.should eq "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"
  end

  it "can hash ripemd-160 correctly" do
    # ripemd-160 hashes taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    ripe = Crypto.ripemd160 "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"
    ripe.should eq "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
  end

  it "can generate base58 representation" do
    # base58 encoding example taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    bs58 = Crypto.base58 "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"
    bs58.should eq "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end
end

# tests for the Bitcoin module
describe Bitcoin do
  # tests a known bitcoin address from a known private key
  it "can generate a valid bitcoin address" do
    # private key and address taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    adr = Bitcoin.address_from_private "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
    adr.should eq "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end
end

# tests for the Ethereum module
describe Ethereum do
  # tests a known ethereum address from a known private key
  it "can generate a valid ethereum address" do
    # private key and address taken from nick's edgeware tweet-storm
    # ref: https://twitter.com/nicksdjohnson/status/1146018827685126144
    adr = Ethereum.address_from_private "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51"
    adr.should eq "0x2Ef1f605AF5d03874eE88773f41c1382ac71C239"
  end

  # implements the eip-55 test cases
  # ref: https://eips.ethereum.org/EIPS/eip-55
  it "passes eip-55 ethereum address mix-case checksums" do
    chk_0 = Ethereum.address_checksum "0x52908400098527886e0f7030069857d2e4169ee7"
    chk_1 = Ethereum.address_checksum "8617e340b3d01fa5f11f306f4090fd50e238070d"
    chk_2 = Ethereum.address_checksum "0xDE709F2102306220921060314715629080E2FB77"
    chk_3 = Ethereum.address_checksum "27B1FDB04752BBC536007A920D24ACB045561C26"
    chk_4 = Ethereum.address_checksum "0x5AaEB6053f3e94c9B9a09F33669435e7eF1bEaED"
    chk_5 = Ethereum.address_checksum "0xFb6916095CA1DF60Bb79cE92Ce3eA74C37C5D359"
    chk_6 = Ethereum.address_checksum "DBf03b407C01e7Cd3cbEA99509D93F8dddc8c6fb"
    chk_7 = Ethereum.address_checksum "d1220a0CF47C7b9bE7a2e6ba89f429762E7B9AdB"
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
      Ethereum.address_checksum "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51"
    end
  end
end