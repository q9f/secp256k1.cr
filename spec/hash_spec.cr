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

# tests for the Secp256k1::Hash module
describe Secp256k1::Hash do
  it "can hash sha3-256 correctly" do
    # sha3-256 hash taken from the crystal-sha3 readme
    # ref: https://github.com/OscarBarrett/crystal-sha3/blob/7b6f6e02196b106ecf0be01da207dbf1e269009b/README.md
    sha3 = Secp256k1::Hash.sha3_string "abc123"
    sha3.should eq "f58fa3df820114f56e1544354379820cff464c9c41cb3ca0ad0b0843c9bb67ee"

    # hash the previous hash again as bytes array instead of a string input
    sha3 = Secp256k1::Hash.sha3 Secp256k1::Hash.hex_to_bin sha3
    sha3.should eq "fb6123314cfb14af7a38a1d6a86a78598a204d7423e25810dad1ec8a8ef5094c"
  end

  it "can hash keccak-256 correctly" do
    # keccak-256 hash taken from the crystal-sha3 readme
    # ref: https://github.com/OscarBarrett/crystal-sha3/blob/7b6f6e02196b106ecf0be01da207dbf1e269009b/README.md
    keccak = Secp256k1::Hash.keccak256_string "abc123"
    keccak.should eq "719accc61a9cc126830e5906f9d672d06eab6f8597287095a2c55a8b775e7016"

    # hash the previous hash again as bytes array instead of a string input
    keccak = Secp256k1::Hash.keccak256 Secp256k1::Hash.hex_to_bin keccak
    keccak.should eq "438a3f652b00153f899189d56c7a70d0b3906b5a6ca4f585de47ac159b630bc0"
  end

  it "can hash sha-256 correctly" do
    # sha-256 hashes taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    sha2 = Secp256k1::Hash.sha256 Secp256k1::Hash.hex_to_bin "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    sha2.should eq "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"

    # hash the previous hash again as string input instead of a bytes array
    sha2 = Secp256k1::Hash.sha256_string sha2
    sha2.should eq "996db65b7f53189aa426cb8166859988d44b4e89eb4305951ababcf79ea3afe0"
  end

  it "can hash sha-512 correctly" do
    sha2 = Secp256k1::Hash.sha512 Secp256k1::Hash.hex_to_bin "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    sha2.should eq "aaa023acaf98be3624463baf58b78dfde25d94b48b81a7f30d0bd408ea9152e657c1d3885d49ed23fb5339c69e56488c13c238334485d8774c402656c88de679"

    # hash the previous hash again as string input instead of a bytes array
    sha2 = Secp256k1::Hash.sha512_string sha2
    sha2.should eq "e6a4912c903ea5ad4d64a8aa349b87ef90798ef6f66949331b6f8d202755bd5a6d7ae72365c6e4183f950440964f7560b2b674e5b62bbbc1c1093ee077445727"
  end

  it "can hash ripemd-160 correctly" do
    # ripemd-160 hashes taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    ripe = Secp256k1::Hash.ripemd160 Secp256k1::Hash.hex_to_bin "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"
    ripe.should eq "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"

    # hash the previous hash again as string input instead of a bytes array
    ripe = Secp256k1::Hash.ripemd160_string ripe
    ripe.should eq "a653c746b9df6f1f21196bf6f80da734073cdc03"
  end

  it "can encode a valid base58 representation" do
    # base58 encoding example taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    bs58 = Secp256k1::Hash.base58_encode "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"
    bs58.should eq "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end

  it "can decode a valid hex string from base58" do
    # base58 encoding example taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    adr = Secp256k1::Hash.base58_decode "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    adr.should eq "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"

    # invalid base58 should raise
    expect_raises Exception, "cannot decode, invalid base58 character: 'l'" do
      inv = Secp256k1::Hash.base58_decode "1PMycacnJaSqwwJqjawXBErnlsZ7RkXUAs"
    end
  end
end
