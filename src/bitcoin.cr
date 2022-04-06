# Copyright 2019-2022 Afr Schoe @q9f
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

require "./secp256k1"
include Secp256k1

# An example implementation of a `Bitcoin` account using an `Secp256k1`
# key-pair and a Bitcoin network version identifier; only for educational
# purposes and should not be used in production.
module Bitcoin
  # The Base-58 alphabet for `Bitcoin` addresses is a Base-64 alphabet without
  # `0`, `O`, `I`, and `l` to omit similar-looking letters.
  BASE_58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  # An example implementation of a `Bitcoin` account using an `Secp256k1`
  # key-pair and a Bitcoin network version identifier; only for educational
  # purposes and should not be used in production.
  class Account
    # The `Secp256k1` keypair for the account.
    getter key : Key
    # The network version indicator.
    getter version : Num
    # The public, uncompressed Bitcoin account address.
    getter address : String
    # The public, compressed Bitcoin account address.
    getter address_compressed : String
    # The private, uncompressed wallet-import format.
    getter wif : String
    # The private, compressed wallet-import format.
    getter wif_compressed : String

    # Creates a Bitcoin account from a given `Secp256k1::Key` keypay and for the
    # specified network version, e.g., `00` for Bitcoin main network. It creates
    # a random account if no parameters are supplied.
    #
    # Parameters:
    # * `key` (`Secp256k1::Key`): the `Secp256k1` keypair for the account.
    # * `version` (`Secp256k1::Num`): the network version indicator.
    #
    # ```
    # priv = Secp256k1::Num.new "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
    # key = Secp256k1::Key.new priv
    # account = Bitcoin::Account.new key
    # # => #<Bitcoin::Account:0x7f2611dcab40
    # #         @key=#<Secp256k1::Key:0x7f261ae90ee0
    # #               @private_key=#<Secp256k1::Num:0x7f261ae93300
    # #                   @hex="18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
    # #                   @dec=11253563012059685825953619222107823549092147699031672238385790369351542642469,
    # #                   @bin=Bytes[24, 225, 74, 123, 106, 48, 127, 66, 106, 148, 248, 17, 71, 1, 231, 200, 231, 116, 231, 249, 164, 126, 44, 32, 53, 219, 41, 162, 6, 50, 23, 37]>,
    # #               @public_key=#<Secp256k1::Point:0x7f261ae90d20
    # #                   @x=#<Secp256k1::Num:0x7f2611dcabc0
    # #                       @hex="50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
    # #                       @dec=36422191471907241029883925342251831624200921388586025344128047678873736520530,
    # #                       @bin=Bytes[80, 134, 58, 214, 74, 135, 174, 138, 47, 232, 60, 26, 241, 168, 64, 60, 181, 63, 83, 228, 134, 216, 81, 29, 173, 138, 4, 136, 126, 91, 35, 82]>,
    # #                   @y=#<Secp256k1::Num:0x7f2611dcab80
    # #                       @hex="2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",
    # #                       @dec=20277110887056303803699431755396003735040374760118964734768299847012543114150,
    # #                       @bin=Bytes[44, 212, 112, 36, 52, 83, 162, 153, 250, 158, 119, 35, 119, 22, 16, 58, 188, 17, 161, 223, 56, 133, 94, 214, 242, 238, 24, 126, 156, 88, 43, 166]>>>,
    # #         @version=#<Secp256k1::Num:0x7f2611dcab00
    # #               @hex="00",
    # #               @dec=0,
    # #               @bin=Bytes[0]>,
    # #         @address="16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
    # #         @address_compressed="1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
    # #         @wif="5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V",
    # #         @wif_compressed="Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C">
    # ```
    def initialize(key = Key.new, version = Num.new "0x00")
      if version.to_big < 0 || version.to_big > 127
        raise "Invalid version byte provided (out of range: #{version.to_prefixed_hex})"
      end
      @key = key
      @version = version
      @address = get_address
      @address_compressed = get_address true
      @wif = get_wif
      @wif_compressed = get_wif true
    end

    # Generates the public address for this account.
    private def get_address(compressed = false) : String
      pub_key = Num.new @key.public_bytes
      if compressed
        pub_key = Num.new @key.public_bytes_compressed
      end
      hash_0 = Util.sha256 pub_key.to_zpadded_bytes pub_key.bin.size
      hash_1 = Util.ripemd160 hash_0.to_zpadded_bytes
      versioned = Util.concat_bytes @version.to_bytes, hash_1.to_zpadded_bytes 20
      hash_2 = Util.sha256 versioned
      hash_3 = Util.sha256 hash_2.to_zpadded_bytes
      binary = Util.concat_bytes versioned, hash_3.to_zpadded_bytes[0, 4]
      encode_base58 Num.new binary
    end

    # Generates the private wallet-import format for this account.
    private def get_wif(compressed = false) : String
      wif_version = Num.new @version.dec + 128
      compression_byte = ""
      if compressed
        compression_byte = "01"
      end
      versioned = Num.new "#{wif_version.to_hex}#{@key.private_hex}#{compression_byte}"
      hash_0 = Util.sha256 versioned
      hash_1 = Util.sha256 hash_0
      binary = Util.concat_bytes versioned.to_bytes, hash_1.to_zpadded_bytes[0, 4]
      encode_base58 Num.new binary
    end

    # Encode a given numeric with BASE58.
    private def encode_base58(num : Num) : String
      big = num.to_big
      hex = num.to_hex
      encoded = String.new
      while big > 0
        big, rem = big.divmod 58
        encoded += BASE_58[rem.to_i % 58]
      end
      i, s = 0, 2
      current_byte = hex[i, s]
      while current_byte.to_i(16) === 0
        encoded = "#{encoded}1"
        i += s
        current_byte = hex[i, s]
      end
      encoded.reverse
    end
  end
end
