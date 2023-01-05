# Copyright 2019-2023 Afri Schoedon @q9f
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

require "../spec_helper"

describe Point do
  it "can create points out of thin air" do
    10.times do
      rand = Point.new Num.new
      rand.uncompressed.size.should eq 130
      rand.compressed.size.should eq 66
    end
    10.times do
      rand = Point.new Num.new, Num.new
      rand.uncompressed.size.should eq 130
      rand.compressed.size.should eq 66
    end
  end

  it "can create public keys from private keys" do
    x = Num.new "5dc864b8207df4cceaee500d148e8d1e0ce363cd952209a768aa376e1aa4eab1"
    y = Num.new "154d459b008a21aa3107b2f2df5ac9acbc7083042f766364685d3e8fbe4a4b4c"
    p = Point.new x, y
    p.uncompressed.should eq "045dc864b8207df4cceaee500d148e8d1e0ce363cd952209a768aa376e1aa4eab1154d459b008a21aa3107b2f2df5ac9acbc7083042f766364685d3e8fbe4a4b4c"
    p.compressed.should eq "025dc864b8207df4cceaee500d148e8d1e0ce363cd952209a768aa376e1aa4eab1"
  end

  it "does not allow invalid private keys" do
    key_too_low = Num.new "0"
    expect_raises Exception, "Invalid scalar: outside of Secp256k1 field dimension." do
      Point.new key_too_low
    end
    key_too_high = Num.new "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    expect_raises Exception, "Invalid scalar: outside of Secp256k1 field dimension." do
      Point.new key_too_high
    end
  end

  it "generates valid public point from private key" do
    priv = Num.new "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"
    p = Point.new priv
    p.x.hex.should eq "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    p.y.hex.should eq "a762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    p.uncompressed.should eq "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    p.compressed.should eq "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    priw = Num.new "55255657523dd1c65a77d3cb53fcd050bf7fc2c11bb0bb6edabdbd41ea51f641"
    q = Point.new priw
    q.uncompressed.should eq "0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf"
    q.compressed.should eq "0314fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267"
  end

  it "can create public keys from coordinates" do
    x = Num.new "5dc864b8207df4cceaee500d148e8d1e0ce363cd952209a768aa376e1aa4eab1"
    y = Num.new "154d459b008a21aa3107b2f2df5ac9acbc7083042f766364685d3e8fbe4a4b4c"
    p = Point.new x, y
    p.uncompressed.should eq "045dc864b8207df4cceaee500d148e8d1e0ce363cd952209a768aa376e1aa4eab1154d459b008a21aa3107b2f2df5ac9acbc7083042f766364685d3e8fbe4a4b4c"
    p.compressed.should eq "025dc864b8207df4cceaee500d148e8d1e0ce363cd952209a768aa376e1aa4eab1"
  end

  it "restores public ec point from public key strings" do
    uncompressed = "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    p = Point.new uncompressed
    p.not_nil!.x.hex.should eq "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    p.not_nil!.y.hex.should eq "a762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
    compressed = "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    q = Point.new compressed
    q.not_nil!.x.hex.should eq "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    q.not_nil!.y.hex.should eq "a762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90"
  end

  it "does not restore invalid points" do
    expect_raises Exception, "Unknown public point format (Invalid size: 64)" do
      Point.new "0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    end
    expect_raises Exception, "Unknown public point format (Invalid size: 90)" do
      Point.new "040791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0aa762fbc6ac0921b8f17025bb"
    end
    expect_raises Exception, "Invalid prefix for compressed public point: 08" do
      Point.new "080791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
    end
  end
end
