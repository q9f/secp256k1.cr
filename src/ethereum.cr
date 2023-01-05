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

require "./secp256k1"
include Secp256k1

# An example implementation of an `Ethereum` account using an `Secp256k1`
# keypair; only for educational purposes and should not be used in production.
module Ethereum
  # An example implementation of an `Ethereum` account using an `Secp256k1`
  # keypair; only for educational purposes and should not be used in production.
  class Account
    # The `Secp256k1` keypair for the account.
    getter key : Key
    # The checksummed Ethereum account address.
    getter address : String

    # Creates an Ethereum account from a given `Secp256k1::Key` keypair.
    # It creates a random account if no keys are supplied.
    #
    # Parameters:
    # * `key` (`Secp256k1::Key`): the `Secp256k1` keypair for the account.
    #
    # ```
    # prv = Secp256k1::Num.new "d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51"
    # key = Secp256k1::Key.new prv
    # Ethereum::Account.new key
    # # => #<Ethereum::Account:0x7fcc10726a60
    # #         @key=#<Secp256k1::Key:0x7fcc19799ee0
    # #             @private_key=#<Secp256k1::Num:0x7fcc1979c300
    # #                 @hex="d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51",
    # #                 @dec=97149512268879514742361644313413872500736768173592718417281501971026009718353,
    # #                 @bin=Bytes[214, 200, 172, 228, 112, 171, 12, 224, 49, 37, 202, 198, 171, 242, 119, 156, 25, 157, 33, 164, 125, 62, 117, 233, 60, 33, 43, 30, 194, 60, 254, 81]>,
    # #             @public_key=#<Secp256k1::Point:0x7fcc19799d20
    # #                 @x=#<Secp256k1::Num:0x7fcc1979c240
    # #                     @hex="bf0cf8c934bd3c57e962fdf2a47e99d6136b047f987ee2e0cb03110cafd92afc",
    # #                     @dec=86414673301778591173569328850396232566766657919369855130423318525027519376124,
    # #                     @bin=Bytes[191, 12, 248, 201, 52, 189, 60, 87, 233, 98, 253, 242, 164, 126, 153, 214, 19, 107, 4, 127, 152, 126, 226, 224, 203, 3, 17, 12, 175, 217, 42, 252]>,
    # #                 @y=#<Secp256k1::Num:0x7fcc1979c200
    # #                     @hex="981974428f8162d3f8fce2f58d4e56341478e87d092aeb3a0edf8af97d638d04",
    # #                     @dec=68796526558321542419405677832866288094027461232937174622925256896107946151172,
    # #                     @bin=Bytes[152, 25, 116, 66, 143, 129, 98, 211, 248, 252, 226, 245, 141, 78, 86, 52, 20, 120, 232, 125, 9, 42, 235, 58, 14, 223, 138, 249, 125, 99, 141, 4]>>>,
    # #         @address="0x2Ef1f605AF5d03874eE88773f41c1382ac71C239">
    # ```
    def initialize(key = Key.new)
      @key = key
      @address = get_address
    end

    # Generates the public address for this account.
    private def get_address : String
      hash = Util.keccak @key.public_bytes[1, 64]
      checksum hash.to_zpadded_hex[24, 40]
    end

    # Ensures the public address is checksummed.
    private def checksum(addr : String) : String
      addr = addr.downcase
      hash = Util.keccak(addr).to_zpadded_hex
      result = "0x"
      i = 0
      while i < addr.size
        k = hash[i].to_i 16
        if k >= 8
          result += "#{addr[i]}".upcase
        else
          result += "#{addr[i]}".downcase
        end
        i += 1
      end
      result
    end
  end
end
