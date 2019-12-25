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

    # hash the previous hash again as string input instead of a bytes array
    sha2 = Crypto.sha256_string sha2
    sha2.should eq "996db65b7f53189aa426cb8166859988d44b4e89eb4305951ababcf79ea3afe0"
  end

  it "can hash ripemd-160 correctly" do
    # ripemd-160 hashes taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    ripe = Crypto.ripemd160 "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"
    ripe.should eq "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
  end

  it "can encode a valid base58 representation" do
    # base58 encoding example taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    bs58 = Crypto.base58_encode "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"
    bs58.should eq "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end

  it "can decode a valid hex string from base58" do
    # base58 encoding example taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    adr = Crypto.base58_decode "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    adr.should eq "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"

    # invalid base58 should raise
    expect_raises Exception, "cannot decode, invalid base58 character: 'l'" do
      inv = Crypto.base58_decode "1PMycacnJaSqwwJqjawXBErnlsZ7RkXUAs"
    end
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

  # generates a mini private key and checks its attributes
  # ref: https://en.bitcoin.it/wiki/Mini_private_key_format
  it "can generate a valid mini private key" do
    mini = Bitcoin.new_mini_private_key

    # should start with capital "S"
    mini[0, 1].should eq "S"

    # should be 30 characters long
    mini.size.should eq 30

    # the hash of the mini key with question mark should start with "00"
    sha2 = Crypto.sha256_string "#{mini}?"
    sha2[0, 2].should eq "00"
  end

  # tests the mini key from the bitcoin wiki
  # ref: https://en.bitcoin.it/wiki/Mini_private_key_format
  it "can generate a valid private key from mini key" do
    mini = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy"
    priv = Bitcoin.private_key_from_mini mini
    priv.should eq BigInt.new "4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab", 16
    sha2 = Crypto.sha256_string "#{mini}?"
    sha2.should eq "000f2453798ad4f951eecced2242eaef3e1cbc8a7c813c203ac7ffe57060355d"
  end

  # tests the wallet import format with the keys from the bitcoin wiki
  # ref: https://en.bitcoin.it/wiki/Wallet_import_format
  it "can provide the correct wallet import format" do
    priv = BigInt.new "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", 16
    wif = Bitcoin.wif_from_private priv
    wif.should eq "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    wif_compr = Bitcoin.wif_compressed_from_private priv
    wif_compr.should eq "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
  end

  # tests the wallet import format with the keys from the bitcoin wiki
  # ref: https://en.bitcoin.it/wiki/Wallet_import_format
  it "can extract private keys from wallet import format" do
    uncm = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    comp = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    priv_uncm = Bitcoin.private_key_from_wif uncm
    priv_comp = Bitcoin.private_key_from_wif comp

    # both should map to the same private key
    priv_uncm.should eq "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
    priv_comp.should eq "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
    priv_comp.should eq priv_uncm

    # should not allow invalid wif
    expect_raises Exception, "invalid wallet import format (invalid wif size: 50)" do
      inv = Bitcoin.private_key_from_wif "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    end
  end

  # tests the wallet import format with the keys from the bitcoin wiki
  # ref: https://en.bitcoin.it/wiki/Wallet_import_format
  # ref: https://bitcoin.stackexchange.com/questions/68065/private-key-to-wif-compressed-which-one-is-correct
  it "can detect invalid wallet import formats" do
    uncm0 = Bitcoin.wif_is_valid? "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    comp0 = Bitcoin.wif_is_valid? "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    uncm1 = Bitcoin.wif_is_valid? "5HpHgWkLaovGWySEFpng1XQ6pdG1TzNWR7SrETvfTRVdKHNXZh8"
    comp1 = Bitcoin.wif_is_valid? "KwDidQJHSE67VJ6MWRvbBKAxhD3F48DvqRT6JRqrjd7MHLBjGF7V"

    # all keys should be valid
    uncm0.should eq true
    comp0.should eq true
    uncm1.should eq true
    comp1.should eq true

    # invalid wif should not pass
    inv0 = Bitcoin.wif_is_valid? "2SaK8jfqHYLmZdtSdWu1XrXCxpU8u2nt4civAPveeX8P2X5ceivrpf"
    inv1 = Bitcoin.wif_is_valid? "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    inv0.should eq false
    inv1.should eq false
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
