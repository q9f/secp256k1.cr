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
{"lineNum":"   15","line":"# Provides a collection of utilities for convenience, e.g., to bind"},
{"lineNum":"   16","line":"# relevant hashing algorithms, or to concatenate byte slices."},
{"lineNum":"   17","line":"module Secp256k1::Util"},
{"lineNum":"   18","line":"  extend self"},
{"lineNum":"   19","line":""},
{"lineNum":"   20","line":"  # Operating a Keccak hash on a binary/number or string literal."},
{"lineNum":"   21","line":"  #"},
{"lineNum":"   22","line":"  # Parameters:"},
{"lineNum":"   23","line":"  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed."},
{"lineNum":"   24","line":"  # * `entropy` (`Int32`): the required entropy (default `256`)."},
{"lineNum":"   25","line":"  #"},
{"lineNum":"   26","line":"  # Returns a `Num` representing the Keccak hash."},
{"lineNum":"   27","line":"  #"},
{"lineNum":"   28","line":"  # ```"},
{"lineNum":"   29","line":"  # Util.keccak(Num.new \"0xdeadbeef\").hex"},
{"lineNum":"   30","line":"  # # => \"d4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1\""},
{"lineNum":"   31","line":"  #"},
{"lineNum":"   32","line":"  # Util.keccak(\"0xdeadbeef\").hex"},
{"lineNum":"   33","line":"  # # => \"4f440a001006a49f24a7de53c04eca3f79aef851ac58e460c9630d044277c8b0\""},
{"lineNum":"   34","line":"  # ```"},
{"lineNum":"   35","line":"  def keccak(data : Num | Bytes | String, entropy = 256) : Num","class":"lineCov","hits":"10","order":"175","possible_hits":"10",},
{"lineNum":"   36","line":"    keccak = Digest::Keccak3.new entropy","class":"lineCov","hits":"3","order":"176","possible_hits":"3",},
{"lineNum":"   37","line":"    if data.is_a? Num"},
{"lineNum":"   38","line":"      return Num.new keccak.update(data.to_bytes).hexdigest","class":"lineCov","hits":"1","order":"287","possible_hits":"1",},
{"lineNum":"   39","line":"    else"},
{"lineNum":"   40","line":"      return Num.new keccak.update(data).hexdigest","class":"lineCov","hits":"2","order":"177","possible_hits":"2",},
{"lineNum":"   41","line":"    end"},
{"lineNum":"   42","line":"  end"},
{"lineNum":"   43","line":""},
{"lineNum":"   44","line":"  # Operating a SHA3 hash on a binary/number or string literal."},
{"lineNum":"   45","line":"  #"},
{"lineNum":"   46","line":"  # Parameters:"},
{"lineNum":"   47","line":"  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed."},
{"lineNum":"   48","line":"  # * `entropy` (`Int32`): the required entropy (default `256`)."},
{"lineNum":"   49","line":"  #"},
{"lineNum":"   50","line":"  # Returns a `Num` representing the SHA3 hash."},
{"lineNum":"   51","line":"  #"},
{"lineNum":"   52","line":"  # ```"},
{"lineNum":"   53","line":"  # Util.sha3(Num.new \"0xdeadbeef\").hex"},
{"lineNum":"   54","line":"  # # => \"352b82608dad6c7ac3dd665bc2666e5d97803cb13f23a1109e2105e93f42c448\""},
{"lineNum":"   55","line":"  #"},
{"lineNum":"   56","line":"  # Util.sha3(\"0xdeadbeef\").hex"},
{"lineNum":"   57","line":"  # # => \"c12811e13ed75afe3e0945ef34e8a25b9d321a46e131c6463731de25a21b39eb\""},
{"lineNum":"   58","line":"  # ```"},
{"lineNum":"   59","line":"  def sha3(data : Num | Bytes | String, entropy = 256) : Num","class":"lineCov","hits":"6","order":"288","possible_hits":"6",},
{"lineNum":"   60","line":"    sha3 = Digest::SHA3.new entropy","class":"lineCov","hits":"2","order":"289","possible_hits":"2",},
{"lineNum":"   61","line":"    if data.is_a? Num"},
{"lineNum":"   62","line":"      return Num.new sha3.update(data.to_bytes).hexdigest","class":"lineCov","hits":"1","order":"291","possible_hits":"1",},
{"lineNum":"   63","line":"    else"},
{"lineNum":"   64","line":"      return Num.new sha3.update(data).hexdigest","class":"lineCov","hits":"1","order":"290","possible_hits":"1",},
{"lineNum":"   65","line":"    end"},
{"lineNum":"   66","line":"  end"},
{"lineNum":"   67","line":""},
{"lineNum":"   68","line":"  # Operating a SHA2-256 hash on a binary/number or string literal."},
{"lineNum":"   69","line":"  #"},
{"lineNum":"   70","line":"  # Parameters:"},
{"lineNum":"   71","line":"  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed."},
{"lineNum":"   72","line":"  #"},
{"lineNum":"   73","line":"  # Returns a `Num` representing the SHA2 hash."},
{"lineNum":"   74","line":"  #"},
{"lineNum":"   75","line":"  # ```"},
{"lineNum":"   76","line":"  # Util.sha256(Num.new \"0xdeadbeef\").hex"},
{"lineNum":"   77","line":"  # # => \"5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953\""},
{"lineNum":"   78","line":"  #"},
{"lineNum":"   79","line":"  # Util.sha256(\"0xdeadbeef\").hex"},
{"lineNum":"   80","line":"  # # => \"4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583\""},
{"lineNum":"   81","line":"  # ```"},
{"lineNum":"   82","line":"  def sha256(data : Num | Bytes | String) : Num","class":"lineCov","hits":"4","order":"117","possible_hits":"4",},
{"lineNum":"   83","line":"    sha2 = OpenSSL::Digest.new \"SHA256\"","class":"lineCov","hits":"3","order":"118","possible_hits":"3",},
{"lineNum":"   84","line":"    if data.is_a? Num"},
{"lineNum":"   85","line":"      return Num.new sha2.update(data.to_bytes).final.hexstring","class":"lineCov","hits":"1","order":"164","possible_hits":"1",},
{"lineNum":"   86","line":"    else"},
{"lineNum":"   87","line":"      return Num.new sha2.update(data).final.hexstring","class":"lineCov","hits":"2","order":"119","possible_hits":"2",},
{"lineNum":"   88","line":"    end"},
{"lineNum":"   89","line":"  end"},
{"lineNum":"   90","line":""},
{"lineNum":"   91","line":"  # Operating a RIPEMD-160 hash on a binary/number or string literal."},
{"lineNum":"   92","line":"  #"},
{"lineNum":"   93","line":"  # Parameters:"},
{"lineNum":"   94","line":"  # * `data` (`Num | Bytes | String`): the binary numeric or string literal to be hashed."},
{"lineNum":"   95","line":"  #"},
{"lineNum":"   96","line":"  # Returns a `Num` representing the RIPEMD hash."},
{"lineNum":"   97","line":"  #"},
{"lineNum":"   98","line":"  # ```"},
{"lineNum":"   99","line":"  # Util.ripemd160(Num.new \"0xdeadbeef\").hex"},
{"lineNum":"  100","line":"  # # => \"226821c2f5423e11fe9af68bd285c249db2e4b5a\""},
{"lineNum":"  101","line":"  #"},
{"lineNum":"  102","line":"  # Util.ripemd160(\"0xdeadbeef\").hex"},
{"lineNum":"  103","line":"  # # => \"4caf817f14e84b564e47afd19966e5d123ee0183\""},
{"lineNum":"  104","line":"  # ```"},
{"lineNum":"  105","line":"  def ripemd160(data : Num | Bytes | String) : Num","class":"lineCov","hits":"4","order":"121","possible_hits":"4",},
{"lineNum":"  106","line":"    ripemd = OpenSSL::Digest.new \"RIPEMD160\"","class":"lineCov","hits":"3","order":"122","possible_hits":"3",},
{"lineNum":"  107","line":"    if data.is_a? Num"},
{"lineNum":"  108","line":"      return Num.new ripemd.update(data.to_bytes).final.hexstring","class":"lineCov","hits":"1","order":"292","possible_hits":"1",},
{"lineNum":"  109","line":"    else"},
{"lineNum":"  110","line":"      return Num.new ripemd.update(data).final.hexstring","class":"lineCov","hits":"2","order":"123","possible_hits":"2",},
{"lineNum":"  111","line":"    end"},
{"lineNum":"  112","line":"  end"},
{"lineNum":"  113","line":""},
{"lineNum":"  114","line":"  # Provides a deterministic secret based on private key and message hash"},
{"lineNum":"  115","line":"  # as defined in RFC-6979."},
{"lineNum":"  116","line":"  #"},
{"lineNum":"  117","line":"  # Ref: [datatracker.ietf.org/doc/html/rfc6979](https://datatracker.ietf.org/doc/html/rfc6979)"},
{"lineNum":"  118","line":"  #"},
{"lineNum":"  119","line":"  # Parameters:"},
{"lineNum":"  120","line":"  # * `priv` (`Num`): the private key or secret number."},
{"lineNum":"  121","line":"  # * `hash` (`Num`): the message hash or arbirtrary data hash."},
{"lineNum":"  122","line":"  # * `order` (`Num`): the order of the curve over `G` (default `N`)."},
{"lineNum":"  123","line":"  #"},
{"lineNum":"  124","line":"  # Returns a deterministically random number of type `Num`."},
{"lineNum":"  125","line":"  #"},
{"lineNum":"  126","line":"  # ```"},
{"lineNum":"  127","line":"  # priv = Num.new \"3b74fcc0b0c419a00d2d9e88b15fbd99e03920138da22e2a00c327b88d24cf45\""},
{"lineNum":"  128","line":"  # hash = Util.sha256 \"Henlo, Wordl\""},
{"lineNum":"  129","line":"  # Util.deterministic_k(priv, hash)"},
{"lineNum":"  130","line":"  # # => #<Secp256k1::Num:0x7f0eb8447280"},
{"lineNum":"  131","line":"  # #          @hex=\"b7ede9a5b5b328ac680be6765213c7b5b2920469bdaaf8070c1fb43cb5c440da\","},
{"lineNum":"  132","line":"  # #          @dec=83193606619515454920331057246310791124858301167609726617990890481932799590618,"},
{"lineNum":"  133","line":"  # #          @bin=Bytes[183, 237, 233, 165, 181, 179, 40, 172, 104, 11, 230, 118, 82, 19, 199, 181, 178, 146, 4, 105, 189, 170, 248, 7, 12, 31, 180, 60, 181, 196, 64, 218]>"},
{"lineNum":"  134","line":"  # ```"},
{"lineNum":"  135","line":"  def deterministic_k(priv : Num, hash : Num, order = N) : Num","class":"lineCov","hits":"4","order":"192","possible_hits":"4",},
{"lineNum":"  136","line":"    order_size = order.hex.size // 2","class":"lineCov","hits":"1","order":"193","possible_hits":"1",},
{"lineNum":"  137","line":"    v = Num.new Bytes.new order_size, 0x01","class":"lineCov","hits":"1","order":"194","possible_hits":"1",},
{"lineNum":"  138","line":"    k = Num.new Bytes.new order_size, 0x00","class":"lineCov","hits":"1","order":"195","possible_hits":"1",},
{"lineNum":"  139","line":"    concat = Util.concat_bytes v.bin, Bytes[0x00]","class":"lineCov","hits":"2","order":"196","possible_hits":"2",},
{"lineNum":"  140","line":"    concat = Util.concat_bytes concat, priv.bin","class":"lineCov","hits":"3","order":"197","possible_hits":"3",},
{"lineNum":"  141","line":"    concat = Util.concat_bytes concat, hash.bin","class":"lineCov","hits":"3","order":"198","possible_hits":"3",},
{"lineNum":"  142","line":"    k = OpenSSL::HMAC.digest(:sha256, k.bin, concat)","class":"lineCov","hits":"3","order":"199","possible_hits":"3",},
{"lineNum":"  143","line":"    v = OpenSSL::HMAC.digest(:sha256, k, v.bin)","class":"lineCov","hits":"2","order":"200","possible_hits":"2",},
{"lineNum":"  144","line":"    concat = Util.concat_bytes v, Bytes[0x00]","class":"lineCov","hits":"2","order":"201","possible_hits":"2",},
{"lineNum":"  145","line":"    concat = Util.concat_bytes concat, priv.bin","class":"lineCov","hits":"3","order":"202","possible_hits":"3",},
{"lineNum":"  146","line":"    concat = Util.concat_bytes concat, hash.bin","class":"lineCov","hits":"3","order":"203","possible_hits":"3",},
{"lineNum":"  147","line":"    k = OpenSSL::HMAC.digest(:sha256, k, concat)","class":"lineCov","hits":"3","order":"204","possible_hits":"3",},
{"lineNum":"  148","line":"    v = OpenSSL::HMAC.digest(:sha256, k, v)","class":"lineCov","hits":"2","order":"205","possible_hits":"2",},
{"lineNum":"  149","line":"    while true"},
{"lineNum":"  150","line":"      t = IO::Memory.new.to_slice","class":"lineCov","hits":"1","order":"206","possible_hits":"1",},
{"lineNum":"  151","line":"      while t.size < order_size","class":"lineCov","hits":"2","order":"207","possible_hits":"2",},
{"lineNum":"  152","line":"        v = OpenSSL::HMAC.digest(:sha256, k, v)","class":"lineCov","hits":"3","order":"208","possible_hits":"3",},
{"lineNum":"  153","line":"        t = Util.concat_bytes t, v","class":"lineCov","hits":"2","order":"209","possible_hits":"2",},
{"lineNum":"  154","line":"      end"},
{"lineNum":"  155","line":"      secret = Num.new t","class":"lineCov","hits":"1","order":"210","possible_hits":"1",},
{"lineNum":"  156","line":"      if secret.dec < order.dec && secret.dec > 0","class":"lineCov","hits":"2","order":"211","possible_hits":"2",},
{"lineNum":"  157","line":"        return secret"},
{"lineNum":"  158","line":"      end"},
{"lineNum":"  159","line":"      increment = Util.concat_bytes v, Bytes[0x00]","class":"lineNoCov","hits":"0","possible_hits":"2",},
{"lineNum":"  160","line":"      k = OpenSSL::HMAC.digest(:sha256, k, increment)","class":"lineNoCov","hits":"0","possible_hits":"3",},
{"lineNum":"  161","line":"      v = OpenSSL::HMAC.digest(:sha256, k, v)","class":"lineNoCov","hits":"0","possible_hits":"2",},
{"lineNum":"  162","line":"    end"},
{"lineNum":"  163","line":"  end"},
{"lineNum":"  164","line":""},
{"lineNum":"  165","line":"  # Concatenates two byte slices in the order provided, i.e., `x|y`."},
{"lineNum":"  166","line":"  #"},
{"lineNum":"  167","line":"  # Parameters:"},
{"lineNum":"  168","line":"  # * `x` (`Bytes`): a byte slice."},
{"lineNum":"  169","line":"  # * `y` (`Bytes`): another byte slice."},
{"lineNum":"  170","line":"  #"},
{"lineNum":"  171","line":"  # Returns a concatenated `Bytes` slice."},
{"lineNum":"  172","line":"  #"},
{"lineNum":"  173","line":"  # ```"},
{"lineNum":"  174","line":"  # Util.concat_bytes Bytes[1, 2, 3], Bytes[9, 8, 7]"},
{"lineNum":"  175","line":"  # # => Bytes[1, 2, 3, 9, 8, 7]"},
{"lineNum":"  176","line":"  # ```"},
{"lineNum":"  177","line":"  def concat_bytes(x : Bytes, y : Bytes) : Bytes","class":"lineCov","hits":"2","order":"125","possible_hits":"2",},
{"lineNum":"  178","line":"    z = IO::Memory.new x.bytesize + y.bytesize","class":"lineCov","hits":"1","order":"126","possible_hits":"1",},
{"lineNum":"  179","line":"    x.each do |b|"},
{"lineNum":"  180","line":"      z.write_bytes UInt8.new b","class":"lineCov","hits":"1","order":"127","possible_hits":"1",},
{"lineNum":"  181","line":"    end"},
{"lineNum":"  182","line":"    y.each do |b|"},
{"lineNum":"  183","line":"      z.write_bytes UInt8.new b","class":"lineCov","hits":"1","order":"128","possible_hits":"1",},
{"lineNum":"  184","line":"    end"},
{"lineNum":"  185","line":"    return z.to_slice","class":"lineCov","hits":"1","order":"129","possible_hits":"1",},
{"lineNum":"  186","line":"  end"},
{"lineNum":"  187","line":"end"},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "run_coverage", "date" : "2022-04-06 16:56:27", "instrumented" : 44, "covered" : 41,};
var merged_data = [];
