require "big"
require "option_parser"

class FF1Cipher
  FEISTEL_MIN = 100
  NUM_ROUNDS = 10
  BLOCK_SIZE = 16

  @radix : Int32
  @max_tlen : Int32
  @tweak : Bytes
  @min_len : Int32
  @max_len : Int64
  @debug : Bool
  @key : Bytes
  @nr : Int32
  @nk : Int32
  @w : Array(UInt32)
  @sbox : Array(UInt8)
  @inv_sbox : Array(UInt8)
  @rcon : Array(UInt8)

  def initialize(@radix : Int32, @max_tlen : Int32, key : String, tweak : String = "", @debug = false)
    # Validar chave
    key_len = key.bytesize
    if ![16, 24, 32].includes?(key_len)
      raise "Key length must be 128, 192 or 256 bits"
    end

    # Validar radix
    if @radix < 2 || @radix > 65536
      raise "Radix must be between 2 and 65536"
    end

    # Validar tweak
    @tweak = tweak.to_slice
    if @tweak.size > @max_tlen
      raise "Tweak exceeds maximum allowed length"
    end

    # Calcular min_len
    @min_len = Math.max(2, (Math.log(FEISTEL_MIN) / Math.log(@radix)).ceil.to_i)
    @max_len = 4_294_967_295_i64

    if @min_len < 2 || @max_len < @min_len
      raise "Invalid minLen, adjust your radix"
    end

    # Chave AES
    @key = key.to_slice

    # Parâmetros AES
    if key_len == 16
      @nr = 10
    elsif key_len == 24
      @nr = 12
    else
      @nr = 14
    end
    @nk = key_len // 4

    # Inicializar S-box
    @sbox = [
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ].map(&.to_u8)

    # Inicializar inverse S-box
    @inv_sbox = [
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
      0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
      0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc9, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
      0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ].map(&.to_u8)

    # Inicializar Rcon
    @rcon = [
      0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
      0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
    ].map(&.to_u8)

    # Inicializar array da chave expandida
    @w = Array(UInt32).new(4 * (@nr + 1), 0_u32)

    # Expandir chave
    (0...@nk).each do |i|
      @w[i] = (@key[4*i].to_u32 << 24) |
              (@key[4*i+1].to_u32 << 16) |
              (@key[4*i+2].to_u32 << 8) |
              @key[4*i+3].to_u32
    end

    (@nk...4 * (@nr + 1)).each do |i|
      temp = @w[i-1]
      if i % @nk == 0
        temp = ((temp << 8) & 0xFFFFFFFF_u32) | (temp >> 24)
        temp = (@sbox[(temp >> 24) & 0xFF].to_u32 << 24) |
               (@sbox[(temp >> 16) & 0xFF].to_u32 << 16) |
               (@sbox[(temp >> 8) & 0xFF].to_u32 << 8) |
               @sbox[temp & 0xFF].to_u32
        temp ^= @rcon[i//@nk - 1].to_u32 << 24
      elsif @nk > 6 && i % @nk == 4
        temp = (@sbox[(temp >> 24) & 0xFF].to_u32 << 24) |
               (@sbox[(temp >> 16) & 0xFF].to_u32 << 16) |
               (@sbox[(temp >> 8) & 0xFF].to_u32 << 8) |
               @sbox[temp & 0xFF].to_u32
      end
      @w[i] = @w[i-@nk] ^ temp
    end

    # Debug da expansão de chave
    if @debug
      puts "DEBUG: Key expansion:"
      (0...4 * (@nr + 1)).each do |i|
        puts "DEBUG: w[#{i}] = #{@w[i].to_s(16).rjust(8, '0')}"
      end
    end
  end

  private def sub_bytes(state : Array(Array(UInt8)))
    (0...4).each do |i|
      (0...4).each do |j|
        state[i][j] = @sbox[state[i][j]]
      end
    end
  end

  private def shift_rows(state : Array(Array(UInt8)))
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
  end

  private def add_round_key(state : Array(Array(UInt8)), round : Int32)
    (0...4).each do |i|
      (0...4).each do |j|
        state[i][j] ^= ((@w[round*4 + j] >> (24 - 8*i)) & 0xFF).to_u8
      end
    end
  end

  private def mix_columns(state : Array(Array(UInt8)))
    (0...4).each do |i|
      s0 = state[0][i]; s1 = state[1][i]; s2 = state[2][i]; s3 = state[3][i]
      state[0][i] = (gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3).to_u8
      state[1][i] = (s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3).to_u8
      state[2][i] = (s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3)).to_u8
      state[3][i] = (gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3)).to_u8
    end
  end

  private def gmul(a : Int32, b : UInt8) : UInt8
    p = 0_u8
    aa = a.to_u8
    bb = b
    8.times do
      if (bb & 1) == 1
        p ^= aa
      end
      hi_bit_set = (aa & 0x80) != 0
      aa <<= 1
      if hi_bit_set
        aa ^= 0x1b_u8
      end
      bb >>= 1
    end
    p
  end

  private def print_state(state, label)
    puts "DEBUG: #{label}"
    (0...4).each do |i|
      line = (0...4).map { |j| state[i][j].to_s(16).rjust(2, '0') }.join
      puts "DEBUG:   #{line}"
    end
  end

  private def aes_encrypt_block(block : Bytes) : Bytes
    puts "DEBUG: AES encrypt block input = #{block.hexstring}" if @debug

    state = Array.new(4) { Array.new(4, 0_u8) }
    (0...4).each do |i|
      (0...4).each do |j|
        state[i][j] = block[i + 4*j]
      end
    end

    print_state(state, "Initial state") if @debug

    add_round_key(state, 0)
    print_state(state, "After AddRoundKey 0") if @debug

    (1...@nr).each do |r|
      sub_bytes(state)
      print_state(state, "After SubBytes #{r}") if @debug
      shift_rows(state)
      print_state(state, "After ShiftRows #{r}") if @debug
      mix_columns(state)
      print_state(state, "After MixColumns #{r}") if @debug
      add_round_key(state, r)
      print_state(state, "After AddRoundKey #{r}") if @debug
    end

    sub_bytes(state)
    print_state(state, "After SubBytes final") if @debug
    shift_rows(state)
    print_state(state, "After ShiftRows final") if @debug
    add_round_key(state, @nr)
    print_state(state, "After AddRoundKey final") if @debug

    output = Bytes.new(16)
    (0...4).each do |i|
      (0...4).each do |j|
        output[i + 4*j] = state[i][j]
      end
    end

    puts "DEBUG: AES encrypt block output = #{output.hexstring}" if @debug
    output
  end

  private def aes_cbc_encrypt(data : Bytes, iv : Bytes = Bytes.new(16, 0_u8)) : Bytes
    if data.size % 16 != 0
      raise "Data must be multiple of 16 bytes"
    end

    num_blocks = data.size // 16
    encrypted_blocks = [] of Bytes
    prev = iv

    puts "DEBUG: CBC encrypt - #{num_blocks} blocks" if @debug
    puts "DEBUG: CBC IV = #{iv.hexstring}" if @debug

    num_blocks.times do |idx|
      block = data[idx * 16, 16]
      
      puts "DEBUG: CBC block #{idx} input = #{block.hexstring}" if @debug
      puts "DEBUG: CBC prev = #{prev.hexstring}" if @debug

      xored = Bytes.new(16) { |j| block[j] ^ prev[j] }
      puts "DEBUG: CBC xored = #{xored.hexstring}" if @debug

      encrypted = aes_encrypt_block(xored)
      puts "DEBUG: CBC encrypted = #{encrypted.hexstring}" if @debug

      encrypted_blocks << encrypted
      prev = encrypted
    end

    # Juntar todos os blocos
    result = Bytes.new(data.size)
    encrypted_blocks.each_with_index do |block, idx|
      block.each_with_index { |byte, j| result[idx * 16 + j] = byte }
    end
    
    puts "DEBUG: CBC result = #{result.hexstring}" if @debug
    result
  end

  private def ciph(input : Bytes) : Bytes
    if input.size % BLOCK_SIZE != 0
      raise "Input length must be multiple of #{BLOCK_SIZE}"
    end

    iv_zero = Bytes.new(BLOCK_SIZE, 0_u8)
    puts "DEBUG: ciph input size = #{input.size}" if @debug

    result = if input.size == BLOCK_SIZE
      puts "DEBUG: Using ECB mode" if @debug
      aes_encrypt_block(input)
    else
      puts "DEBUG: Using CBC mode" if @debug
      aes_cbc_encrypt(input, iv_zero)
    end

    puts "DEBUG: ciph result = #{result.hexstring}" if @debug
    result
  end

  private def prf(input : Bytes) : Bytes
    puts "DEBUG: PRF input = #{input.hexstring}" if @debug
    encrypted = ciph(input)
    if encrypted.size < BLOCK_SIZE
      raise "PRF output too small: #{encrypted.size}"
    end
    result = encrypted[-BLOCK_SIZE..-1]
    puts "DEBUG: PRF result = #{result.hexstring}" if @debug
    result
  end

  private def str_to_int(s : String) : BigInt
    result = BigInt.new(0)
    s.each_char do |c|
      val = case c
      when '0'..'9' then c.ord - '0'.ord
      when 'a'..'z' then c.ord - 'a'.ord + 10
      when 'A'..'Z' then c.ord - 'A'.ord + 10
      else raise "Invalid character: #{c}"
      end
      result = result * @radix + val
    end
    result
  end

  private def int_to_str(n : BigInt, length : Int32) : String
    if n == 0
      return "0" * length
    end

    digits = [] of Char
    num = n
    while num > 0
      rem = (num % @radix).to_i
      if rem < 10
        digits << (rem + '0'.ord).chr
      else
        digits << (rem - 10 + 'a'.ord).chr
      end
      num //= @radix
    end

    digits.reverse.join.rjust(length, '0')
  end

  private def int_to_bytes(n : BigInt, num_bytes : Int32) : Bytes
    bytes = Bytes.new(num_bytes, 0_u8)
    temp = n
    (num_bytes - 1).downto(0) do |i|
      bytes[i] = (temp & 0xFF).to_u8
      temp >>= 8
    end
    bytes
  end

  private def bytes_to_int(bytes : Bytes) : BigInt
    result = BigInt.new(0)
    bytes.each do |b|
      result = (result << 8) | b
    end
    result
  end

  def encrypt(plaintext : String, tweak : Bytes? = nil) : String
    tweak = tweak || @tweak

    n = plaintext.size
    t = tweak.size

    puts "DEBUG: t = #{t}" if @debug
    puts "DEBUG: tweak bytes = #{tweak.hexstring}" if @debug

    if n < @min_len || n > @max_len
      raise "Length must be between #{@min_len} and #{@max_len}"
    end

    if tweak.size > @max_tlen
      raise "Tweak exceeds maximum length"
    end

    plaintext.each_char do |c|
      val = case c
      when '0'..'9' then c.ord - '0'.ord
      when 'a'..'z' then c.ord - 'a'.ord + 10
      when 'A'..'Z' then c.ord - 'A'.ord + 10
      else raise "Invalid character"
      end
      if val >= @radix
        raise "Character '#{c}' not in radix #{@radix}"
      end
    end

    u = n // 2
    v = n - u

    puts "DEBUG: n=#{n}, t=#{t}, u=#{u}, v=#{v}" if @debug
    puts "DEBUG: plaintext='#{plaintext}', a='#{plaintext[0, u]}', b='#{plaintext[u, v]}'" if @debug

    a = plaintext[0, u]
    b = plaintext[u, v]

    num_a = str_to_int(a)
    num_b = str_to_int(b)

    puts "DEBUG: num_a=#{num_a}, num_b=#{num_b}" if @debug

    b_len = ((Math.log2(@radix) * v).ceil / 8).ceil.to_i
    d = 4 * ((b_len + 3) // 4) + 4

    max_j = (d + 15) // 16

    num_pad = (-t - b_len - 1) % 16
    if num_pad < 0
      num_pad += 16
    end

    puts "DEBUG: b_len=#{b_len}, d=#{d}, max_j=#{max_j}, num_pad=#{num_pad}" if @debug

    p = Bytes.new(16)
    p[0] = 0x01
    p[1] = 0x02
    p[2] = 0x01
    p[3] = 0x00
    p[4] = ((@radix >> 8) & 0xFF).to_u8
    p[5] = (@radix & 0xFF).to_u8
    p[6] = 0x0a
    p[7] = u.to_u8
    p[8] = ((n >> 24) & 0xFF).to_u8
    p[9] = ((n >> 16) & 0xFF).to_u8
    p[10] = ((n >> 8) & 0xFF).to_u8
    p[11] = (n & 0xFF).to_u8
    p[12] = ((t >> 24) & 0xFF).to_u8
    p[13] = ((t >> 16) & 0xFF).to_u8
    p[14] = ((t >> 8) & 0xFF).to_u8
    p[15] = (t & 0xFF).to_u8

    puts "DEBUG: P = #{p.hexstring}" if @debug

    len_q = t + b_len + 1 + num_pad
    len_pq = 16 + len_q

    buf = Bytes.new(len_q + len_pq + (max_j - 1) * 16, 0_u8)

    mod_u = @radix.to_big_i ** u
    mod_v = @radix.to_big_i ** v

    puts "DEBUG: mod_u=#{mod_u}, mod_v=#{mod_v}" if @debug

    (0...NUM_ROUNDS).each do |i|
      puts "DEBUG: Round #{i}" if @debug

      q = buf[0, len_q]
      (0...t).each { |j| q[j] = tweak[j] }
      q[t + num_pad] = i.to_u8

      b_bytes = int_to_bytes(num_b, b_len)

      ((t + num_pad + 1)...len_q).each { |j| q[j] = 0 }

      start_pos = len_q - b_bytes.size
      (0...b_bytes.size).each { |j| q[start_pos + j] = b_bytes[j] }

      puts "DEBUG: Q = #{q.hexstring}" if @debug

      pq = buf[len_q, len_pq]
      (0...16).each { |j| pq[j] = p[j] }
      (0...len_q).each { |j| pq[16 + j] = q[j] }

      puts "DEBUG: PQ = #{pq.hexstring}" if @debug

      r = prf(pq)

      y_buf = buf[len_q + len_pq - 16, d + (max_j - 1) * 16]
      (0...[16, d].min).each { |j| y_buf[j] = r[j] }

      (1...max_j).each do |j|
        offset = (j - 1) * 16
        j_bytes = int_to_bytes(BigInt.new(j), 8)
        (0...8).each { |k| y_buf[offset + 16 + k] = (r[k] ^ j_bytes[k]).to_u8 }
        (8...16).each { |k| y_buf[offset + 16 + k] = r[k] }

        block = y_buf[offset + 16, 16]
        encrypted = ciph(block)
        (0...16).each { |k| y_buf[offset + 16 + k] = encrypted[k] }
      end

      y_bytes = y_buf[0, d]
      num_y = bytes_to_int(y_bytes)

      puts "DEBUG: num_y=#{num_y}" if @debug

      num_c = num_a + num_y

      if i.even?
        num_c %= mod_u
      else
        num_c %= mod_v
      end

      puts "DEBUG: num_c=#{num_c}" if @debug

      num_a, num_b = num_b, num_c
      puts "DEBUG: num_a=#{num_a}, num_b=#{num_b}" if @debug
    end

    result = int_to_str(num_a, u) + int_to_str(num_b, v)
    puts "DEBUG: result=#{result}" if @debug
    result
  end

  def decrypt(ciphertext : String, tweak : Bytes? = nil) : String
    tweak = tweak || @tweak

    n = ciphertext.size
    t = tweak.size

    if n < @min_len || n > @max_len
      raise "Length must be between #{@min_len} and #{@max_len}"
    end

    if tweak.size > @max_tlen
      raise "Tweak exceeds maximum length"
    end

    ciphertext.each_char do |c|
      val = case c
      when '0'..'9' then c.ord - '0'.ord
      when 'a'..'z' then c.ord - 'a'.ord + 10
      when 'A'..'Z' then c.ord - 'A'.ord + 10
      else raise "Invalid character"
      end
      if val >= @radix
        raise "Character '#{c}' not in radix #{@radix}"
      end
    end

    u = n // 2
    v = n - u

    a = ciphertext[0, u]
    b = ciphertext[u, v]

    num_a = str_to_int(a)
    num_b = str_to_int(b)

    b_len = ((Math.log2(@radix) * v).ceil / 8).ceil.to_i
    d = 4 * ((b_len + 3) // 4) + 4

    max_j = (d + 15) // 16

    num_pad = (-t - b_len - 1) % 16
    if num_pad < 0
      num_pad += 16
    end

    p = Bytes.new(16)
    p[0] = 0x01
    p[1] = 0x02
    p[2] = 0x01
    p[3] = 0x00
    p[4] = ((@radix >> 8) & 0xFF).to_u8
    p[5] = (@radix & 0xFF).to_u8
    p[6] = 0x0a
    p[7] = u.to_u8
    p[8] = ((n >> 24) & 0xFF).to_u8
    p[9] = ((n >> 16) & 0xFF).to_u8
    p[10] = ((n >> 8) & 0xFF).to_u8
    p[11] = (n & 0xFF).to_u8
    p[12] = ((t >> 24) & 0xFF).to_u8
    p[13] = ((t >> 16) & 0xFF).to_u8
    p[14] = ((t >> 8) & 0xFF).to_u8
    p[15] = (t & 0xFF).to_u8

    len_q = t + b_len + 1 + num_pad
    len_pq = 16 + len_q

    buf = Bytes.new(len_q + len_pq + (max_j - 1) * 16, 0_u8)

    mod_u = @radix.to_big_i ** u
    mod_v = @radix.to_big_i ** v

    (NUM_ROUNDS - 1).downto(0) do |i|
      q = buf[0, len_q]
      (0...t).each { |j| q[j] = tweak[j] }
      q[t + num_pad] = i.to_u8

      a_bytes = int_to_bytes(num_a, b_len)

      ((t + num_pad + 1)...len_q).each { |j| q[j] = 0 }

      start_pos = len_q - a_bytes.size
      (0...a_bytes.size).each { |j| q[start_pos + j] = a_bytes[j] }

      pq = buf[len_q, len_pq]
      (0...16).each { |j| pq[j] = p[j] }
      (0...len_q).each { |j| pq[16 + j] = q[j] }

      r = prf(pq)

      y_buf = buf[len_q + len_pq - 16, d + (max_j - 1) * 16]
      (0...[16, d].min).each { |j| y_buf[j] = r[j] }

      (1...max_j).each do |j|
        offset = (j - 1) * 16
        j_bytes = int_to_bytes(BigInt.new(j), 8)
        (0...8).each { |k| y_buf[offset + 16 + k] = (r[k] ^ j_bytes[k]).to_u8 }
        (8...16).each { |k| y_buf[offset + 16 + k] = r[k] }

        block = y_buf[offset + 16, 16]
        encrypted = ciph(block)
        (0...16).each { |k| y_buf[offset + 16 + k] = encrypted[k] }
      end

      y_bytes = y_buf[0, d]
      num_y = bytes_to_int(y_bytes)

      num_c = num_b - num_y

      if i.even?
        num_c %= mod_u
      else
        num_c %= mod_v
      end

      if num_c < 0
        num_c += i.even? ? mod_u : mod_v
      end

      num_b, num_a = num_a, num_c
    end

    int_to_str(num_a, u) + int_to_str(num_b, v)
  end
end

# CLI
VERSION = "1.0.0"

record Config,
  command : String,
  radix : Int32,
  key : String,
  tweak : String,
  input : String,
  file : String,
  output : String,
  max_tlen : Int32,
  help : Bool,
  version : Bool,
  debug : Bool

def show_help
  puts <<-HELP
FF1 Format-Preserving Encryption
================================

Usage:
  ff1 encrypt [options]
  ff1 decrypt [options]

Options:
  --radix=NUM        Base (2-65536, default: 10)
  --key=STRING       Encryption key (16, 24, 32 bytes)
  --tweak=STRING     Tweak value
  --input=STRING     Input text
  --file=FILE        Input file
  --output=FILE      Output file
  --max-tlen=NUM     Max tweak length (default: 32)
  --debug            Debug output
  --help             Show help
  --version          Show version
HELP
end

def parse_args : Config
  cmd = ""
  radix = 10
  key = ""
  tweak = ""
  input = ""
  file = ""
  output = ""
  max_tlen = 32
  help = false
  version = false
  debug = false

  args = ARGV.dup
  if args.size > 0 && !args[0].starts_with?("--")
    cmd = args[0]
    args.shift
  end

  parser = OptionParser.new do |parser|
    parser.on("--radix=NUM", "Numeric base") { |r| radix = r.to_i }
    parser.on("--key=STRING", "Encryption key") { |k| key = k }
    parser.on("--tweak=STRING", "Tweak value") { |t| tweak = t }
    parser.on("--input=STRING", "Input text") { |i| input = i }
    parser.on("--file=FILE", "Input file") { |f| file = f }
    parser.on("--output=FILE", "Output file") { |o| output = o }
    parser.on("--max-tlen=NUM", "Maximum tweak length") { |m| max_tlen = m.to_i }
    parser.on("--debug", "Enable debug output") { debug = true }
    parser.on("--help", "Show help") { help = true }
    parser.on("--version", "Show version") { version = true }
    parser.parse(args)
  end

  Config.new(
    command: cmd,
    radix: radix,
    key: key,
    tweak: tweak,
    input: input,
    file: file,
    output: output,
    max_tlen: max_tlen,
    help: help,
    version: version,
    debug: debug
  )
end

def read_input(config)
  if !config.file.empty?
    File.read(config.file).strip
  elsif !config.input.empty?
    config.input
  else
    puts "Enter text (Ctrl+D to end):"
    STDIN.gets_to_end.strip
  end
end

def validate_config(config)
  if config.help
    show_help
    exit(0)
  end

  if config.version
    puts "FF1 v#{VERSION}"
    exit(0)
  end

  if config.command.empty?
    puts "Error: No command"
    show_help
    exit(1)
  end

  unless {"encrypt", "decrypt"}.includes?(config.command)
    puts "Error: Invalid command"
    exit(1)
  end

  if config.key.empty?
    puts "Error: Key required"
    exit(1)
  end

  if config.radix < 2 || config.radix > 65536
    puts "Error: Radix must be 2-65536"
    exit(1)
  end

  if config.tweak.bytesize > config.max_tlen
    puts "Error: Tweak too long"
    exit(1)
  end
end

def main
  config = parse_args
  validate_config(config)
  input = read_input(config)

  begin
    cipher = FF1Cipher.new(
      config.radix,
      config.max_tlen,
      config.key,
      config.tweak,
      config.debug
    )

    result = config.command == "encrypt" ?
      cipher.encrypt(input) :
      cipher.decrypt(input)

    if config.output.empty?
      puts result
    else
      File.write(config.output, result)
      puts "Output written to #{config.output}"
    end
  rescue ex
    puts "Error: #{ex.message}"
    exit(1)
  end
end

main
