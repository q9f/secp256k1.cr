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
  end

  it "can hash keccak-256 correctly" do
    # keccak-256 hash taken from the crystal-sha3 readme
    # ref: https://github.com/OscarBarrett/crystal-sha3/blob/7b6f6e02196b106ecf0be01da207dbf1e269009b/README.md
    keccak = Crypto.keccak256_string "abc123"
    keccak.should eq "719accc61a9cc126830e5906f9d672d06eab6f8597287095a2c55a8b775e7016"
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
  it "can generate a valid bitcoin address" do
    # private key and address taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    adr = Bitcoin.address_from_private "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
    adr.should eq "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end
end

# tests for the Ethereum module
describe Ethereum do
  it "can generate a valid ethereum address" do
    # private key and address taken from nick's edgeware tweet-storm
    # ref: https://twitter.com/nicksdjohnson/status/1146018827685126144
    adr = Ethereum.address_from_private "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51"
    adr.should eq "0x2Ef1f605AF5d03874eE88773f41c1382ac71C239"
  end
end
