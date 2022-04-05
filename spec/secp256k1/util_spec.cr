require "../spec_helper"

describe Util do
  it "can hash keccak correctly" do
    # keccak-256 hash taken from the crystal-sha3 readme
    # ref: https://github.com/OscarBarrett/crystal-sha3/blob/7b6f6e02196b106ecf0be01da207dbf1e269009b/README.md
    keccak = Util.keccak "abc123"
    keccak.to_hex.should eq "719accc61a9cc126830e5906f9d672d06eab6f8597287095a2c55a8b775e7016"

    # hash the previous hash again as bytes array instead of a string input
    keccak = Util.keccak keccak
    keccak.to_hex.should eq "438a3f652b00153f899189d56c7a70d0b3906b5a6ca4f585de47ac159b630bc0"
  end

  it "can hash sha3 correctly" do
    # sha3-256 hash taken from the crystal-sha3 readme
    # ref: https://github.com/OscarBarrett/crystal-sha3/blob/7b6f6e02196b106ecf0be01da207dbf1e269009b/README.md
    sha3 = Util.sha3 "abc123"
    sha3.to_hex.should eq "f58fa3df820114f56e1544354379820cff464c9c41cb3ca0ad0b0843c9bb67ee"

    # hash the previous hash again as bytes array instead of a string input
    sha3 = Util.sha3 sha3
    sha3.to_hex.should eq "fb6123314cfb14af7a38a1d6a86a78598a204d7423e25810dad1ec8a8ef5094c"
  end

  it "can hash sha256 correctly" do
    # sha-256 hashes taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    sha2 = Util.sha256 Num.new "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    sha2.to_hex.should eq "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"

    # hash the previous hash again as string input instead of a bytes array
    sha2 = Util.sha256 sha2.to_hex
    sha2.to_hex.should eq "996db65b7f53189aa426cb8166859988d44b4e89eb4305951ababcf79ea3afe0"
  end

  it "can hash ripemd160 correctly" do
    # ripemd-160 hashes taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    ripe = Util.ripemd160 Num.new "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"
    ripe.to_hex.should eq "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"

    # hash the previous hash again as string input instead of a bytes array
    ripe = Util.ripemd160 ripe.to_hex
    ripe.to_hex.should eq "a653c746b9df6f1f21196bf6f80da734073cdc03"
  end
end
