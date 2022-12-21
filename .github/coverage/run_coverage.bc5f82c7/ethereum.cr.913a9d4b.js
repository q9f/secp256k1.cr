var data = {lines:[
{"lineNum":"    1","line":"# Copyright 2019-2022 Afr Schoe @q9f"},
{"lineNum":"    2","line":"#"},
{"lineNum":"    3","line":"# Licensed under the Apache License, Version 2.0 (the \"License\");"},
{"lineNum":"    4","line":"# you may not use this file except in compliance with the License."},
{"lineNum":"    5","line":"# You may obtain a copy of the License at"},
{"lineNum":"    6","line":"#"},
{"lineNum":"    7","line":"#     http://www.apache.org/licenses/LICENSE-2.0"},
{"lineNum":"    8","line":"#"},
{"lineNum":"    9","line":"# Unless required by applicable law or agreed to in writing, software"},
{"lineNum":"   10","line":"# distributed under the License is distributed on an \"AS IS\" BASIS,"},
{"lineNum":"   11","line":"# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied."},
{"lineNum":"   12","line":"# See the License for the specific language governing permissions and"},
{"lineNum":"   13","line":"# limitations under the License."},
{"lineNum":"   14","line":""},
{"lineNum":"   15","line":"require \"./secp256k1\""},
{"lineNum":"   16","line":"include Secp256k1"},
{"lineNum":"   17","line":""},
{"lineNum":"   18","line":"# An example implementation of an `Ethereum` account using an `Secp256k1`"},
{"lineNum":"   19","line":"# keypair; only for educational purposes and should not be used in production."},
{"lineNum":"   20","line":"module Ethereum"},
{"lineNum":"   21","line":"  # An example implementation of an `Ethereum` account using an `Secp256k1`"},
{"lineNum":"   22","line":"  # keypair; only for educational purposes and should not be used in production."},
{"lineNum":"   23","line":"  class Account"},
{"lineNum":"   24","line":"    # The `Secp256k1` keypair for the account."},
{"lineNum":"   25","line":"    getter key : Key"},
{"lineNum":"   26","line":"    # The checksummed Ethereum account address."},
{"lineNum":"   27","line":"    getter address : String"},
{"lineNum":"   28","line":""},
{"lineNum":"   29","line":"    # Creates an Ethereum account from a given `Secp256k1::Key` keypair."},
{"lineNum":"   30","line":"    # It creates a random account if no keys are supplied."},
{"lineNum":"   31","line":"    #"},
{"lineNum":"   32","line":"    # Parameters:"},
{"lineNum":"   33","line":"    # * `key` (`Secp256k1::Key`): the `Secp256k1` keypair for the account."},
{"lineNum":"   34","line":"    #"},
{"lineNum":"   35","line":"    # ```"},
{"lineNum":"   36","line":"    # prv = Secp256k1::Num.new \"d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51\""},
{"lineNum":"   37","line":"    # key = Secp256k1::Key.new prv"},
{"lineNum":"   38","line":"    # Ethereum::Account.new key"},
{"lineNum":"   39","line":"    # # => #<Ethereum::Account:0x7fcc10726a60"},
{"lineNum":"   40","line":"    # #         @key=#<Secp256k1::Key:0x7fcc19799ee0"},
{"lineNum":"   41","line":"    # #             @private_key=#<Secp256k1::Num:0x7fcc1979c300"},
{"lineNum":"   42","line":"    # #                 @hex=\"d6c8ace470ab0ce03125cac6abf2779c199d21a47d3e75e93c212b1ec23cfe51\","},
{"lineNum":"   43","line":"    # #                 @dec=97149512268879514742361644313413872500736768173592718417281501971026009718353,"},
{"lineNum":"   44","line":"    # #                 @bin=Bytes[214, 200, 172, 228, 112, 171, 12, 224, 49, 37, 202, 198, 171, 242, 119, 156, 25, 157, 33, 164, 125, 62, 117, 233, 60, 33, 43, 30, 194, 60, 254, 81]>,"},
{"lineNum":"   45","line":"    # #             @public_key=#<Secp256k1::Point:0x7fcc19799d20"},
{"lineNum":"   46","line":"    # #                 @x=#<Secp256k1::Num:0x7fcc1979c240"},
{"lineNum":"   47","line":"    # #                     @hex=\"bf0cf8c934bd3c57e962fdf2a47e99d6136b047f987ee2e0cb03110cafd92afc\","},
{"lineNum":"   48","line":"    # #                     @dec=86414673301778591173569328850396232566766657919369855130423318525027519376124,"},
{"lineNum":"   49","line":"    # #                     @bin=Bytes[191, 12, 248, 201, 52, 189, 60, 87, 233, 98, 253, 242, 164, 126, 153, 214, 19, 107, 4, 127, 152, 126, 226, 224, 203, 3, 17, 12, 175, 217, 42, 252]>,"},
{"lineNum":"   50","line":"    # #                 @y=#<Secp256k1::Num:0x7fcc1979c200"},
{"lineNum":"   51","line":"    # #                     @hex=\"981974428f8162d3f8fce2f58d4e56341478e87d092aeb3a0edf8af97d638d04\","},
{"lineNum":"   52","line":"    # #                     @dec=68796526558321542419405677832866288094027461232937174622925256896107946151172,"},
{"lineNum":"   53","line":"    # #                     @bin=Bytes[152, 25, 116, 66, 143, 129, 98, 211, 248, 252, 226, 245, 141, 78, 86, 52, 20, 120, 232, 125, 9, 42, 235, 58, 14, 223, 138, 249, 125, 99, 141, 4]>>>,"},
{"lineNum":"   54","line":"    # #         @address=\"0x2Ef1f605AF5d03874eE88773f41c1382ac71C239\">"},
{"lineNum":"   55","line":"    # ```"},
{"lineNum":"   56","line":"    def initialize(key = Key.new)","class":"lineCov","hits":"3","order":"170","possible_hits":"3",},
{"lineNum":"   57","line":"      @key = key","class":"lineCov","hits":"1","order":"171","possible_hits":"1",},
{"lineNum":"   58","line":"      @address = get_address","class":"lineCov","hits":"1","order":"172","possible_hits":"1",},
{"lineNum":"   59","line":"    end"},
{"lineNum":"   60","line":""},
{"lineNum":"   61","line":"    # Generates the public address for this account."},
{"lineNum":"   62","line":"    private def get_address : String","class":"lineCov","hits":"2","order":"173","possible_hits":"2",},
{"lineNum":"   63","line":"      hash = Util.keccak @key.public_bytes[1, 64]","class":"lineCov","hits":"1","order":"174","possible_hits":"1",},
{"lineNum":"   64","line":"      checksum hash.to_zpadded_hex[24, 40]","class":"lineCov","hits":"1","order":"178","possible_hits":"1",},
{"lineNum":"   65","line":"    end"},
{"lineNum":"   66","line":""},
{"lineNum":"   67","line":"    # Ensures the public address is checksummed."},
{"lineNum":"   68","line":"    private def checksum(addr : String) : String","class":"lineCov","hits":"2","order":"179","possible_hits":"2",},
{"lineNum":"   69","line":"      addr = addr.downcase","class":"lineCov","hits":"1","order":"180","possible_hits":"1",},
{"lineNum":"   70","line":"      hash = Util.keccak(addr).to_zpadded_hex","class":"lineCov","hits":"1","order":"181","possible_hits":"1",},
{"lineNum":"   71","line":"      result = \"0x\"","class":"lineCov","hits":"1","order":"182","possible_hits":"1",},
{"lineNum":"   72","line":"      i = 0","class":"lineCov","hits":"1","order":"183","possible_hits":"1",},
{"lineNum":"   73","line":"      while i < addr.size","class":"lineCov","hits":"1","order":"184","possible_hits":"1",},
{"lineNum":"   74","line":"        k = hash[i].to_i 16","class":"lineCov","hits":"1","order":"185","possible_hits":"1",},
{"lineNum":"   75","line":"        if k >= 8","class":"lineCov","hits":"2","order":"186","possible_hits":"2",},
{"lineNum":"   76","line":"          result += \"#{addr[i]}\".upcase","class":"lineCov","hits":"1","order":"188","possible_hits":"1",},
{"lineNum":"   77","line":"        else"},
{"lineNum":"   78","line":"          result += \"#{addr[i]}\".downcase","class":"lineCov","hits":"1","order":"187","possible_hits":"1",},
{"lineNum":"   79","line":"        end"},
{"lineNum":"   80","line":"        i += 1","class":"linePartCov","hits":"1","order":"189","possible_hits":"2",},
{"lineNum":"   81","line":"      end"},
{"lineNum":"   82","line":"      result"},
{"lineNum":"   83","line":"    end"},
{"lineNum":"   84","line":"  end"},
{"lineNum":"   85","line":"end"},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "run_coverage", "date" : "2022-04-06 16:56:27", "instrumented" : 17, "covered" : 17,};
var merged_data = [];