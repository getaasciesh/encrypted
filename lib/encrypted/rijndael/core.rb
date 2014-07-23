module Encrypted
    class Rijndael
        class Core
            @@rounds_by_block_size={
                4=>10,
                6=>12,
                8=>14
            }
            
            def self.round_count(block_words, key_words) #:nodoc:
                biggest_words=if(block_words > key_words)
                    block_words
                else
                    key_words
                end
                @@rounds_by_block_size[biggest_words]
            end
            def self.round_constants(block_words, key_words) #:nodoc:
                @@round_constants ||= {}
                @@round_constants[block_words] ||= {}
                unless(@@round_constants[block_words][key_words]) then
                  temp_v=1
                  p_round_constant=[0,1].map {|i| [i, 0, 0, 0].pack("C*")}
                  
                  p_round_constant+=
                  (2 .. (block_words * (round_count(block_words, key_words) + 1)/key_words).to_i).to_a.map {
                      #0x1000000<<($_-1)
                      [(temp_v=Core.dot(02,temp_v)),0,0,0].pack("C*")
                  }
                  @@round_constants[block_words][key_words] = p_round_constant
                end
                @@round_constants[block_words][key_words]
            end
            def self.expand_key_le6(key, block_words) #:nodoc
              # For short (128-bit, 192-bit) keys this is used to expand the key to blocklen*(rounds+1) bits
                
                #expanded_key=key;
                ek_words=key.unpack("N*").map {|number| Encrypted::ByteStream.new([number].pack("N"))}
            
                key_words = key.length / 4
                p_round_constant = round_constants(block_words, key_words)
            
                rounds=round_count(block_words, key_words)
                
                (key_words .. block_words * (rounds + 1)-1).each do
                    |i|

                    p_temp=ek_words[i-1]
                    
                    
                    if(i % key_words == 0) 
                        
                            t_byte=p_temp.byte_at(0)
                            p_temp[0 .. 2]=p_temp[1 .. 3]
                            p_temp.byte_at(3, t_byte)
                        
                        # tr would be great here again.
                        p_temp=Encrypted::ByteStream.new(Core.sbox_block(p_temp))
                        p_temp^=p_round_constant[(i/key_words).to_i]
                    end
                    ek_words[i]=p_temp^ek_words[i-key_words]
                    i+=1
                end
                #puts ek_words.to_s
                expanded_key=Array(rounds+1)
                (0 .. rounds).each do
                    |round|
                    expanded_key[round]=Encrypted::ByteStream.new(ek_words[round*block_words, block_words].join(""))
                end
                return expanded_key; 
            end
                    
            def self.expand_key_gt6(key, block_words) #:nodoc:
              # For long (256-bit) keys this is used to expand the key to blocklen*(rounds+1) bits
                
                #expanded_key=key
                ek_words=key.unpack("N*").map {|number| Encrypted::ByteStream.new([number].pack("N"))}
            
                key_words = key.length / 4
                p_round_constant = round_constants(block_words, key_words)

                rounds=round_count(block_words, key_words)

                (key_words .. block_words * (rounds + 1)-1).each do 
                    |i|

                    p_temp=ek_words[i-1]
                    if(i % key_words == 0) 
                        
                            t_byte=p_temp.byte_at(0)
                            p_temp[0 .. 2]=p_temp[1 .. 3]
                            p_temp.byte_at(3, t_byte)
            
                        # tr would be great here again.
                        p_temp=Encrypted::ByteStream.new(Core.sbox_block(p_temp))
                        p_temp^=p_round_constant[(i/key_words).to_i]
                      
                    elsif(i % key_words == 4) 
                        p_temp=Core.sbox_block(p_temp)
                    end
                    ek_words[i]=ek_words[i-key_words]^p_temp
                end
                expanded_key=Array(rounds+1)
                (0 .. rounds).each do
                    |round|
                    expanded_key[round]=Encrypted::ByteStream.new(ek_words[round*block_words, block_words].join(""))
                end
                return expanded_key;
            end

            def self.roundn_times(block, expanded_key, rounds, direction) #:nodoc:
              case(direction)
              when :forward then
                (1 .. rounds-1).each do 
                  |current_round|
                  block=Core.roundn(block, expanded_key[current_round])
                end
              when :reverse then
                (1 .. rounds-1).to_a.reverse.each do 
                    |current_round|
                    block=Core.inv_roundn(block, expanded_key[current_round])
                end
              else
                raise "Unsupported round direction"
              end
              block
            end
            def self.roundn(input, round_key) #:nodoc:
                block_words = input.length / 4
                row_len=block_words;
            
                input=sbox_block(input)
                input=shift_rows(input)       
                # Tune this - jim
                input=mix_column(input)
                
                return round0(input, round_key)
            end
            
            def self.inv_roundn(input, round_key) #:nodoc:
                block_words = input.length / 4
                
                input=round0(input, round_key)
                row_len=block_words
                input=inv_mix_column(input)

                
                input=inv_shift_rows(input)
                # convert to use tr for the s-box ?
                input=inv_sbox_block(input)
                
                return input
            end
            
            def self.roundl(input, round_key) #:nodoc:
                # convert to use tr for the s-box

                input=sbox_block(input)
                input=shift_rows(input)
                return round0(input, round_key)
            end
            
            def self.inv_roundl(input, round_key) #:nodoc:
                # convert to use tr for the s-box
                input=round0(input, round_key)
                input=inv_sbox_block(input)
                input=inv_shift_rows(input)
                #input=bytes_n.pack("C*")  
                return input
            end


            def self.round0(input, round_key) #:nodoc:
                return round_key^input;
            end
            def self.make_shiftrow_map  #:nodoc:
              shift_for_block_len={
                4=>[0,1,2,3],
                6=>[0,1,2,3],
                8=>[0,1,3,4],
              }
                @@inv_shiftrow_map=(0 .. 0xff).map {Array.new}
                @@shiftrow_map=(0 .. 0xff).map {Array.new}  
                shift_for_block_len.keys.each do
                    |block_len|
                    row_len=block_len;
                    state_b=(0 .. (row_len*4)-1).to_a;
                    col_len=4;
                    c=shift_for_block_len[block_len];
                    (0 .. c.length-1).each do
                        |row_n| 
                        # Grab the lossage first
                        next unless c[row_n] > 0;
                        d1=Array.new
                        d2=Array.new
                        (row_len-c[row_n] .. row_len-1).map {|col| row_n+col_len*col}.each do
                            |offset|
                            d1+=state_b[offset,1]
                        end 
                        (0 .. row_len-c[row_n]-1).map {|col| row_n+col_len*col}.each do
                            |offset|
                            d2+=state_b[offset,1]
                        end  
                        
                  (0 .. row_len-1).map {|col| row_n+col_len*col}.each do
                            |offset|
                            state_b[offset]=d1.shift||d2.shift
                        end
                    end
                    @@inv_shiftrow_map[block_len]=state_b;
                    (0 .. state_b.length-1).each do
                        |offset|
                        @@shiftrow_map[block_len][state_b[offset]]=offset;
                    end
                end
            end
            
            make_shiftrow_map

            def self.shift_rows(state_b) #:nodoc:
              row_len=state_b.length/4
              
              state_o=@@shiftrow_map[row_len].map do
                |offset|
                state_b.byte_at(offset)
              end
              return Encrypted::ByteStream.new(state_o.pack("C*"))
            end
            
            def self.inv_shift_rows(state_b) #:nodoc:
              col_len=4;
              row_len=state_b.length/4;
              
                state_o=@@inv_shiftrow_map[row_len].map do
                    |offset|
                    state_b.byte_at(offset)
                end
                return Encrypted::ByteStream.new(state_o.pack("C*"))
            end
            

            POLYNOMIAL_SPACE=0x11b
            COLUMN_SIZE=4

            def self.sbox_block(input)
                return Encrypted::ByteStream.new(input.unpack("C*").map do
                    |byte| 
                    @@sbox[byte]
                end.pack("C*"))
            end
    
            def self.inv_sbox_block(input)
                return Encrypted::ByteStream.new(input.unpack("C*").map do
                    |byte| 
                    @@inv_sbox[byte]
                end.pack("C*"))
            end
                    
            def self.mix_column(col)
                block_words=col.length/COLUMN_SIZE
                r_col=Array.new
                (0 .. (block_words-1)).each {
                    |current_word|
                    r_col+=[
                    (@@dot_cache[02][col.byte_at((current_word*4)+0)] ^ 
                        @@dot_cache[03][col.byte_at((current_word*4)+1)] ^ 
                            col.byte_at((current_word*4)+2) ^ 
                                col.byte_at((current_word*4)+3) ),
                    ( col.byte_at((current_word*4)+0) ^ 
                        @@dot_cache[02][col.byte_at((current_word*4)+1)] ^ 
                            @@dot_cache[03][col.byte_at((current_word*4)+2)] ^ 
                                col.byte_at((current_word*4)+3) ),
                    ( col.byte_at((current_word*4)+0) ^ 
                        col.byte_at((current_word*4)+1) ^ 
                            @@dot_cache[02][col.byte_at((current_word*4)+2)] ^ 
                                @@dot_cache[03][col.byte_at((current_word*4)+3)]),
                    (@@dot_cache[03][col.byte_at((current_word*4)+0)] ^ 
                        col.byte_at((current_word*4)+1) ^ 
                            col.byte_at((current_word*4)+2) ^ 
                                @@dot_cache[02][col.byte_at((current_word*4)+3)])]
                }
                return Encrypted::ByteStream.new(r_col.pack("C*"))
            end
            
            # The inverse of the above
            
            def self.inv_mix_column(col)
                block_words=col.length/COLUMN_SIZE
                r_col=Array.new
                (0 .. (block_words-1)).each { |current_block|
                    r_col+=[
                    (@@dot_cache[0x0e][col.byte_at((current_block*4)+0)] ^ 
                        @@dot_cache[0x0b][col.byte_at((current_block*4)+1)] ^ 
                            @@dot_cache[0x0d][col.byte_at((current_block*4)+2)] ^ 
                                @@dot_cache[0x09][col.byte_at((current_block*4)+3)]),
                    (@@dot_cache[0x09][col.byte_at((current_block*4)+0)] ^ 
                        @@dot_cache[0x0e][col.byte_at((current_block*4)+1)] ^ 
                            @@dot_cache[0x0b][col.byte_at((current_block*4)+2)] ^ 
                                @@dot_cache[0x0d][col.byte_at((current_block*4)+3)]),
                    (@@dot_cache[0x0d][col.byte_at((current_block*4)+0)] ^ 
                        @@dot_cache[0x09][col.byte_at((current_block*4)+1)] ^ 
                            @@dot_cache[0x0e][col.byte_at((current_block*4)+2)] ^ 
                                @@dot_cache[0x0b][col.byte_at((current_block*4)+3)]),
                    (@@dot_cache[0x0b][col.byte_at((current_block*4)+0)] ^ 
                        @@dot_cache[0x0d][col.byte_at((current_block*4)+1)] ^ 
                            @@dot_cache[0x09][col.byte_at((current_block*4)+2)] ^ 
                                @@dot_cache[0x0e][col.byte_at((current_block*4)+3)])
                ]}     
                return Encrypted::ByteStream.new(r_col.pack("C*"))
            end
                
            def self.xtime(a)
                a*=2
                if( a & 0x100 > 0 )
                    a^=0x1b
                end
                a&=0xff
                return a
            end            
            
            def self.dot(a, b)
                return 0 unless(a > 0 and b > 0)
                
                result=0
                tv=a
                (0 .. 7).each do
                    |i|
                    if(b & (1<<i) > 0)
                        result^=tv
                    end
                    tv=xtime(tv)
                end
                return result
            end
            

            # _Not_ the same as dot()
            # Multiplies a by b. In polynomial space. Without capping the value.
            def self.mul(a, b)
                result=0
                tv=a
                (0 .. 7).each do
                    |i|
                    if(b & (1<<i) > 0)
                        result^=tv
                    end
                    tv<<=1
                end
                return result
            end
            
            # The inverse of mul() above.
            
            def self.div(a, b)
                acc=a
                tv=b
                result=0
                (0 .. 7).to_a.reverse.each do
                    | i |
                    tv=b<<i
    
                    if( (tv&~acc) < acc  or (acc^tv) <= (1<<i))
                        result|=(1<<i)
                        acc^=tv
                    end
                end
                return result
            end

            # 8-bit number in, 8-bit number out
            def self.mult_inverse(num)
                return 0 unless num > 0
                remainder=[POLYNOMIAL_SPACE, num]
                auxiliary=[0,1]
            
                if(remainder[1]==1)
                   return 1
                end
                i=2
                while remainder[i-1]!=1
                    quotient=div(remainder[i-2], remainder[i-1])
                    multiplied=mul(remainder[i-1], quotient)
                    
                    remainder[i]=remainder[i-2]^multiplied
                    auxiliary[i]=mul(quotient,auxiliary[i-1]) ^ auxiliary[i-2]
                    if (i>10)
                        raise "BUG: Multiplicative inverse should never exceed 10 iterations"
                    end
                    i+=1
                end
                return auxiliary[i-1]
            end

            def self.sbox(b)
                c=0x63
                b=mult_inverse(b)
                result=b
                (1 .. 4).each do
                    |i|
                    b_t=((b<<i)&0xff)|(b>>(8-i))
                    result^=b_t
                end
                return result^c
            end

            # Startup caching follows
            
            unless(defined? @@all_cached)
                @@sbox=(0 .. 255).to_a.map { |input| sbox(input)}
                @@inv_sbox=Array.new(256)
                (0 .. 255).each do
                    |input| 
                    @@inv_sbox[@@sbox[input]]=input
                end
                @@dot_cache=(0 .. 0xf).map {Array.new(256)}
                [0x2, 0x3, 0x9, 0xb, 0xd, 0xe].each do 
                    # These are the only numbers we need.
                    |a|
                    (0 .. 0xff).each do
                        |b|
                        @@dot_cache[a][b]=dot(a, b)
                    end
                end
                @@all_cached=1
            end

        end
        
    end
end
