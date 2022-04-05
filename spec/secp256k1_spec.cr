require "./spec_helper"

describe Secp256k1 do
  it "has some version string" do
    VERSION.should eq "0.5.0"
  end

  it "has correct constants" do
    P.to_hex.should eq "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    N.to_hex.should eq "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    G.uncompressed.should eq "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    G.compressed.should eq "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  end
end
