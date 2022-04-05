require "../spec_helper"

describe Num do
  it "can create numeric types out of thin air" do
    10.times do
      rand = Num.new
      rand.to_big.should be > 0
      rand.to_big.should be < N.to_big
      rand.to_zpadded_hex.size.should eq 64
      rand.to_zpadded_bytes.size.should eq 32
    end
  end

  it "can create numeric types from strings" do
    some = Num.new "8421ca1da93ce5f18e1f"
    some.to_big.should eq 623975682276074590408223u128
    some.to_bytes.should eq Bytes[132, 33, 202, 29, 169, 60, 229, 241, 142, 31]
    some.to_zpadded_bytes.should eq Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 132, 33, 202, 29, 169, 60, 229, 241, 142, 31]
    some.to_hex.should eq "8421ca1da93ce5f18e1f"
    some.to_prefixed_hex.should eq "0x8421ca1da93ce5f18e1f"
    some.to_zpadded_hex.should eq "000000000000000000000000000000000000000000008421ca1da93ce5f18e1f"
  end

  it "can create numeric types from 0x-prefixed strings" do
    some = Num.new "0xf284757fec556200a4f1"
    some.to_big.should eq 1145256125817859742934257u128
    some.to_bytes.should eq Bytes[242, 132, 117, 127, 236, 85, 98, 0, 164, 241]
    some.to_zpadded_bytes.should eq Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 242, 132, 117, 127, 236, 85, 98, 0, 164, 241]
    some.to_hex.should eq "f284757fec556200a4f1"
    some.to_prefixed_hex.should eq "0xf284757fec556200a4f1"
    some.to_zpadded_hex.should eq "00000000000000000000000000000000000000000000f284757fec556200a4f1"
  end

  it "can create numeric types from numbers" do
    other = Num.new BigInt.new 327966575684879933363363u128
    other.to_big.should eq 327966575684879933363363u128
    other.to_bytes.should eq Bytes[69, 115, 26, 139, 160, 2, 36, 181, 212, 163]
    other.to_zpadded_bytes.should eq Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69, 115, 26, 139, 160, 2, 36, 181, 212, 163]
    other.to_hex.should eq "45731a8ba00224b5d4a3"
    other.to_prefixed_hex.should eq "0x45731a8ba00224b5d4a3"
    other.to_zpadded_hex.should eq "0000000000000000000000000000000000000000000045731a8ba00224b5d4a3"
  end

  it "can create numeric types from slices" do
    more = Num.new Bytes[58, 174, 20, 102, 8, 54, 78, 214, 14, 170]
    more.to_big.should eq 277108459346622611328682u128
    more.to_bytes.should eq Bytes[58, 174, 20, 102, 8, 54, 78, 214, 14, 170]
    more.to_zpadded_bytes.should eq Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 174, 20, 102, 8, 54, 78, 214, 14, 170]
    more.to_hex.should eq "3aae146608364ed60eaa"
    more.to_prefixed_hex.should eq "0x3aae146608364ed60eaa"
    more.to_zpadded_hex.should eq "000000000000000000000000000000000000000000003aae146608364ed60eaa"
  end

  it "can does not create invalid hex types" do
    expect_raises Exception, "Invalid hex data provided: 'Lorem Ipsum'" do
      Num.new "Lorem Ipsum"
    end
    expect_raises Exception, "Invalid hex data provided: 'Foo Bar Baz'" do
      Num.new "0xFoo Bar Baz"
    end
  end
end
