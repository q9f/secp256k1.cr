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
{"lineNum":"   15","line":"# Provides a class to conveniently handle big numbers on the elliptic"},
{"lineNum":"   16","line":"# curve. It allows to easily access decimal, hexadecimal, and binary"},
{"lineNum":"   17","line":"# representations of the numeric. In addition, it implements some"},
{"lineNum":"   18","line":"# utilities such as zpadding or asserting hexadecimal strings. It\'s suited"},
{"lineNum":"   19","line":"# to temporarily handle unencrypted private keys."},
{"lineNum":"   20","line":"#"},
{"lineNum":"   21","line":"# Properties:"},
{"lineNum":"   22","line":"# * `hex` (`String`): the hexadecimal string representation of the number."},
{"lineNum":"   23","line":"# * `dec` (`BigInt`): the decimal big-integer representation of the number."},
{"lineNum":"   24","line":"# * `bin` (`Bytes`): the binary bytes-slice represenation of the number."},
{"lineNum":"   25","line":"class Secp256k1::Num"},
{"lineNum":"   26","line":"  # The hexadecimal string representation of the number."},
{"lineNum":"   27","line":"  property hex : String"},
{"lineNum":"   28","line":"  # The decimal big-integer representation of the number."},
{"lineNum":"   29","line":"  property dec : BigInt"},
{"lineNum":"   30","line":"  # The binary bytes-slice represenation of the number."},
{"lineNum":"   31","line":"  property bin : Slice(UInt8)"},
{"lineNum":"   32","line":""},
{"lineNum":"   33","line":"  # Creates a random number using `Random::Secure` that can be used as"},
{"lineNum":"   34","line":"  # a secret (private key)."},
{"lineNum":"   35","line":"  #"},
{"lineNum":"   36","line":"  # ```"},
{"lineNum":"   37","line":"  # Num.new"},
{"lineNum":"   38","line":"  # # => #<Secp256k1::Num:0x7ff3d98013c0"},
{"lineNum":"   39","line":"  # #          @hex=\"568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d\","},
{"lineNum":"   40","line":"  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,"},
{"lineNum":"   41","line":"  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>"},
{"lineNum":"   42","line":"  # ```"},
{"lineNum":"   43","line":"  def initialize","class":"lineCov","hits":"3","order":"169","possible_hits":"3",},
{"lineNum":"   44","line":"    hex = \"0\"","class":"lineCov","hits":"1","order":"170","possible_hits":"1",},
{"lineNum":"   45","line":"    key = 0","class":"lineCov","hits":"1","order":"171","possible_hits":"1",},
{"lineNum":"   46","line":"    until key > 0 && key < N.to_big","class":"lineCov","hits":"2","order":"172","possible_hits":"2",},
{"lineNum":"   47","line":"      hex = Random::Secure.hex 32","class":"lineCov","hits":"1","order":"173","possible_hits":"1",},
{"lineNum":"   48","line":"      key = BigInt.new hex, 16","class":"lineCov","hits":"1","order":"174","possible_hits":"1",},
{"lineNum":"   49","line":"    end"},
{"lineNum":"   50","line":"    @hex = hex","class":"linePartCov","hits":"1","order":"175","possible_hits":"2",},
{"lineNum":"   51","line":"    @dec = BigInt.new key","class":"linePartCov","hits":"1","order":"176","possible_hits":"2",},
{"lineNum":"   52","line":"    @bin = hex.hexbytes","class":"lineCov","hits":"1","order":"177","possible_hits":"1",},
{"lineNum":"   53","line":"  end"},
{"lineNum":"   54","line":""},
{"lineNum":"   55","line":"  # Creates a number from a hexadecimal string literal."},
{"lineNum":"   56","line":"  #"},
{"lineNum":"   57","line":"  # Parameters:"},
{"lineNum":"   58","line":"  # * `hex` (`String`): a hexadecimal string representating the number."},
{"lineNum":"   59","line":"  #"},
{"lineNum":"   60","line":"  # ```"},
{"lineNum":"   61","line":"  # Num.new \"568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d\""},
{"lineNum":"   62","line":"  # # => #<Secp256k1::Num:0x7fb934585480"},
{"lineNum":"   63","line":"  # #          @hex=\"568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d\","},
{"lineNum":"   64","line":"  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,"},
{"lineNum":"   65","line":"  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>"},
{"lineNum":"   66","line":"  # ```"},
{"lineNum":"   67","line":"  def initialize(hex : String)","class":"lineCov","hits":"4","order":"2","possible_hits":"4",},
{"lineNum":"   68","line":"    hex = assert_hexadecimal hex","class":"lineCov","hits":"1","order":"3","possible_hits":"1",},
{"lineNum":"   69","line":"    hex = \"0#{hex}\" if hex.size % 2 != 0","class":"lineCov","hits":"1","order":"11","possible_hits":"1",},
{"lineNum":"   70","line":"    @hex = hex","class":"lineCov","hits":"1","order":"12","possible_hits":"1",},
{"lineNum":"   71","line":"    @dec = BigInt.new hex, 16","class":"lineCov","hits":"1","order":"13","possible_hits":"1",},
{"lineNum":"   72","line":"    @bin = hex.hexbytes","class":"lineCov","hits":"1","order":"14","possible_hits":"1",},
{"lineNum":"   73","line":"  end"},
{"lineNum":"   74","line":""},
{"lineNum":"   75","line":"  # Creates a number from a big integer numeric."},
{"lineNum":"   76","line":"  #"},
{"lineNum":"   77","line":"  # Parameters:"},
{"lineNum":"   78","line":"  # * `dec` (`BigInt`): the decimal big-integer representating the number."},
{"lineNum":"   79","line":"  #"},
{"lineNum":"   80","line":"  # ```"},
{"lineNum":"   81","line":"  # Num.new BigInt.new \"39142835565766237398843902819171565157710677457569850027793715608438337348717\""},
{"lineNum":"   82","line":"  # # => #<Secp256k1::Num:0x7fb934585480"},
{"lineNum":"   83","line":"  # #          @hex=\"568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d\","},
{"lineNum":"   84","line":"  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,"},
{"lineNum":"   85","line":"  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>"},
{"lineNum":"   86","line":"  # ```"},
{"lineNum":"   87","line":"  def initialize(num : BigInt)","class":"lineCov","hits":"4","order":"51","possible_hits":"4",},
{"lineNum":"   88","line":"    hex = num.to_s 16","class":"lineCov","hits":"1","order":"52","possible_hits":"1",},
{"lineNum":"   89","line":"    hex = \"0#{hex}\" if hex.size % 2 != 0","class":"lineCov","hits":"1","order":"53","possible_hits":"1",},
{"lineNum":"   90","line":"    @hex = hex","class":"lineCov","hits":"1","order":"54","possible_hits":"1",},
{"lineNum":"   91","line":"    @dec = num","class":"lineCov","hits":"1","order":"55","possible_hits":"1",},
{"lineNum":"   92","line":"    @bin = hex.hexbytes","class":"lineCov","hits":"1","order":"56","possible_hits":"1",},
{"lineNum":"   93","line":"  end"},
{"lineNum":"   94","line":""},
{"lineNum":"   95","line":"  # Creates a number from a binary bytes slice."},
{"lineNum":"   96","line":"  #"},
{"lineNum":"   97","line":"  # Parameters:"},
{"lineNum":"   98","line":"  # * `bin` (`Bytes`): the binary bytes-slice represenating the number."},
{"lineNum":"   99","line":"  #"},
{"lineNum":"  100","line":"  # ```"},
{"lineNum":"  101","line":"  # Num.new Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]"},
{"lineNum":"  102","line":"  # # => #<Secp256k1::Num:0x7fb934585480"},
{"lineNum":"  103","line":"  # #          @hex=\"568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d\","},
{"lineNum":"  104","line":"  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,"},
{"lineNum":"  105","line":"  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>"},
{"lineNum":"  106","line":"  # ```"},
{"lineNum":"  107","line":"  def initialize(bin : Slice(UInt8))","class":"lineCov","hits":"4","order":"107","possible_hits":"4",},
{"lineNum":"  108","line":"    @hex = bin.hexstring","class":"lineCov","hits":"1","order":"108","possible_hits":"1",},
{"lineNum":"  109","line":"    @dec = BigInt.new bin.hexstring, 16","class":"lineCov","hits":"1","order":"109","possible_hits":"1",},
{"lineNum":"  110","line":"    @bin = bin","class":"lineCov","hits":"1","order":"110","possible_hits":"1",},
{"lineNum":"  111","line":"  end"},
{"lineNum":"  112","line":""},
{"lineNum":"  113","line":"  # Returns an unprefixed hexadecimal string representation."},
{"lineNum":"  114","line":"  #"},
{"lineNum":"  115","line":"  # ```"},
{"lineNum":"  116","line":"  # Num.new(Bytes[137]).to_hex"},
{"lineNum":"  117","line":"  # # => \"89\""},
{"lineNum":"  118","line":"  # ```"},
{"lineNum":"  119","line":"  def to_hex : String"},
{"lineNum":"  120","line":"    @hex"},
{"lineNum":"  121","line":"  end"},
{"lineNum":"  122","line":""},
{"lineNum":"  123","line":"  # Returns an `0x`-prefixed hexadecimal string representation."},
{"lineNum":"  124","line":"  #"},
{"lineNum":"  125","line":"  # ```"},
{"lineNum":"  126","line":"  # Num.new(Bytes[137]).to_prefixed_hex"},
{"lineNum":"  127","line":"  # # => \"0x89\""},
{"lineNum":"  128","line":"  # ```"},
{"lineNum":"  129","line":"  def to_prefixed_hex : String","class":"lineCov","hits":"2","order":"198","possible_hits":"2",},
{"lineNum":"  130","line":"    \"0x#{@hex}\"","class":"lineCov","hits":"1","order":"199","possible_hits":"1",},
{"lineNum":"  131","line":"  end"},
{"lineNum":"  132","line":""},
{"lineNum":"  133","line":"  # Returns a z-padded hexadecimal string representation."},
{"lineNum":"  134","line":"  #"},
{"lineNum":"  135","line":"  # Parameters:"},
{"lineNum":"  136","line":"  # * `length` (`Int`): the byte-size of the final z-padded hex-string (default `32`)."},
{"lineNum":"  137","line":"  #"},
{"lineNum":"  138","line":"  # ```"},
{"lineNum":"  139","line":"  # Num.new(Bytes[137]).to_zpadded_hex"},
{"lineNum":"  140","line":"  # # => \"0000000000000000000000000000000000000000000000000000000000000089\""},
{"lineNum":"  141","line":"  # ```"},
{"lineNum":"  142","line":"  def to_zpadded_hex(length = 32) : String","class":"lineCov","hits":"4","order":"25","possible_hits":"4",},
{"lineNum":"  143","line":"    zpadded_hex = @hex","class":"lineCov","hits":"1","order":"26","possible_hits":"1",},
{"lineNum":"  144","line":"    while zpadded_hex.size < length * 2","class":"linePartCov","hits":"1","order":"27","possible_hits":"2",},
{"lineNum":"  145","line":"      zpadded_hex = \"0#{zpadded_hex}\"","class":"lineCov","hits":"1","order":"192","possible_hits":"1",},
{"lineNum":"  146","line":"    end"},
{"lineNum":"  147","line":"    zpadded_hex"},
{"lineNum":"  148","line":"  end"},
{"lineNum":"  149","line":""},
{"lineNum":"  150","line":"  # Returns a big-integer representation of the number."},
{"lineNum":"  151","line":"  #"},
{"lineNum":"  152","line":"  # ```"},
{"lineNum":"  153","line":"  # Num.new(Bytes[137]).to_big"},
{"lineNum":"  154","line":"  # # => 137"},
{"lineNum":"  155","line":"  # ```"},
{"lineNum":"  156","line":"  def to_big : BigInt"},
{"lineNum":"  157","line":"    @dec"},
{"lineNum":"  158","line":"  end"},
{"lineNum":"  159","line":""},
{"lineNum":"  160","line":"  # Returns a binary byte-slice representation of the number."},
{"lineNum":"  161","line":"  #"},
{"lineNum":"  162","line":"  # ```"},
{"lineNum":"  163","line":"  # Num.new(\"0x89\").to_bytes"},
{"lineNum":"  164","line":"  # # => Bytes[137]"},
{"lineNum":"  165","line":"  # ```"},
{"lineNum":"  166","line":"  def to_bytes : Bytes"},
{"lineNum":"  167","line":"    @bin"},
{"lineNum":"  168","line":"  end"},
{"lineNum":"  169","line":""},
{"lineNum":"  170","line":"  # Returns a z-padded byte-slice binary representation."},
{"lineNum":"  171","line":"  #"},
{"lineNum":"  172","line":"  # Parameters:"},
{"lineNum":"  173","line":"  # * `length` (`Int`): the byte-size of the final z-padded slice (default `32`)."},
{"lineNum":"  174","line":"  #"},
{"lineNum":"  175","line":"  # ```"},
{"lineNum":"  176","line":"  # Num.new(Bytes[137]).to_zpadded_bytes"},
{"lineNum":"  177","line":"  # # => Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137]"},
{"lineNum":"  178","line":"  # ```"},
{"lineNum":"  179","line":"  def to_zpadded_bytes(length = 32) : Bytes","class":"lineCov","hits":"3","order":"183","possible_hits":"3",},
{"lineNum":"  180","line":"    zpadded_bytes = @bin","class":"lineCov","hits":"1","order":"184","possible_hits":"1",},
{"lineNum":"  181","line":"    byte_zero = Bytes[0]","class":"lineCov","hits":"1","order":"185","possible_hits":"1",},
{"lineNum":"  182","line":"    while zpadded_bytes.size < length","class":"lineCov","hits":"1","order":"186","possible_hits":"1",},
{"lineNum":"  183","line":"      slice_size = zpadded_bytes.size + 1","class":"lineNoCov","hits":"0","possible_hits":"1",},
{"lineNum":"  184","line":"      zpadded_slice = Slice(UInt8).new slice_size","class":"lineCov","hits":"1","order":"193","possible_hits":"1",},
{"lineNum":"  185","line":"      slice_pointer = zpadded_slice.to_unsafe","class":"lineCov","hits":"1","order":"194","possible_hits":"1",},
{"lineNum":"  186","line":"      byte_zero.copy_to(slice_pointer, 0)","class":"lineCov","hits":"1","order":"195","possible_hits":"1",},
{"lineNum":"  187","line":"      slice_pointer += 1","class":"lineCov","hits":"1","order":"196","possible_hits":"1",},
{"lineNum":"  188","line":"      zpadded_bytes.copy_to(slice_pointer, zpadded_bytes.size)","class":"lineCov","hits":"1","order":"197","possible_hits":"1",},
{"lineNum":"  189","line":"      zpadded_bytes = zpadded_slice","class":"lineCov","hits":"2","order":"187","possible_hits":"2",},
{"lineNum":"  190","line":"    end"},
{"lineNum":"  191","line":"    zpadded_bytes"},
{"lineNum":"  192","line":"  end"},
{"lineNum":"  193","line":""},
{"lineNum":"  194","line":"  # Assists to determine wether a hex-string is prefixed."},
{"lineNum":"  195","line":"  private def is_prefixed?(hex : String) : Bool","class":"lineCov","hits":"2","order":"6","possible_hits":"2",},
{"lineNum":"  196","line":"    prefix_match = /\\A0x/.match hex","class":"lineCov","hits":"2","order":"7","possible_hits":"2",},
{"lineNum":"  197","line":"    unless prefix_match.nil?","class":"lineCov","hits":"1","order":"8","possible_hits":"1",},
{"lineNum":"  198","line":"      return true"},
{"lineNum":"  199","line":"    else"},
{"lineNum":"  200","line":"      return false"},
{"lineNum":"  201","line":"    end"},
{"lineNum":"  202","line":"  end"},
{"lineNum":"  203","line":""},
{"lineNum":"  204","line":"  # Assists to remove a `0x`-hex prefix."},
{"lineNum":"  205","line":"  private def remove_prefix(hex : String) : String","class":"lineCov","hits":"1","order":"201","possible_hits":"1",},
{"lineNum":"  206","line":"    if is_prefixed? hex","class":"lineCov","hits":"1","order":"202","possible_hits":"1",},
{"lineNum":"  207","line":"      return hex[2..-1]","class":"lineCov","hits":"1","order":"203","possible_hits":"1",},
{"lineNum":"  208","line":"    else"},
{"lineNum":"  209","line":"      return hex"},
{"lineNum":"  210","line":"    end"},
{"lineNum":"  211","line":"  end"},
{"lineNum":"  212","line":""},
{"lineNum":"  213","line":"  # Assists to assert wether a `String` is hexadecimal or not."},
{"lineNum":"  214","line":"  private def assert_hexadecimal(hex : String) : String","class":"lineCov","hits":"2","order":"4","possible_hits":"2",},
{"lineNum":"  215","line":"    if is_prefixed? hex","class":"lineCov","hits":"1","order":"5","possible_hits":"1",},
{"lineNum":"  216","line":"      hex = remove_prefix hex","class":"lineCov","hits":"1","order":"200","possible_hits":"1",},
{"lineNum":"  217","line":"    end"},
{"lineNum":"  218","line":"    hex_match = /\\A[0-9a-fA-F]*\\z/.match hex","class":"lineCov","hits":"2","order":"9","possible_hits":"2",},
{"lineNum":"  219","line":"    unless hex_match.nil?","class":"lineCov","hits":"1","order":"10","possible_hits":"1",},
{"lineNum":"  220","line":"      return hex_match.string"},
{"lineNum":"  221","line":"    else"},
{"lineNum":"  222","line":"      raise \"Invalid hex data provided: \'#{hex}\'\"","class":"lineCov","hits":"1","order":"204","possible_hits":"1",},
{"lineNum":"  223","line":"    end"},
{"lineNum":"  224","line":"  end"},
{"lineNum":"  225","line":"end"},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "run_coverage", "date" : "2022-04-06 11:52:18", "instrumented" : 54, "covered" : 53,};
var merged_data = [];
