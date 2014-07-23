unless(defined? Encrypted::ByteStream)
	require 'encrypted/bytestream'
  Encrypted::ByteStream.strict_mode = true
end
# This is to help testing
unless(defined? Encrypted::Rijndael::Core)
	require "encrypted/rijndael/core"
end

module Encrypted
=begin rdoc
Encrypted::Rijndael allows you to encrypt single blocks of data using the encrypt() and decrypt() methods
below.

You probably want to use some kind of CBC module with this.
=end
    class Rijndael

    
        
        @@valid_blocksizes_bytes=[16, 24, 32]
        @@valid_keysizes_bytes=[16, 24, 32]

=begin rdoc
The new() function here takes only one argument: the key to use, as a String (or similar). Valid lengths
are 16, 24 or 32 bytes, and you should ensure that this value is sufficiently random. Most people will
choose 16-byte (128-bit) keys, but a longer key will take longer to crack if security is of unusually
high importance for you.
=end
        def initialize(new_key)
 						self.key = new_key
						@current_block_length = nil # This makes it easier to adjust in #block=
        end

				attr_reader :key

				# If you want to, you can assign a new key to an existing object.
				def key=(new_key)
					raise "Invalid key length: #{new_key.length}" unless(self.class.key_sizes_supported.find {|size| size==new_key.length})
					@key = new_key
					@key_words=@key.length/4
					@expanded_key = nil
					@round_count = nil
				end
				def expand_key #:nodoc:
						return @expanded_key if(@expanded_key)
						@expanded_key=(@key_words>6)? Core.expand_key_gt6(key, @block_words):
								Core.expand_key_le6(key, @block_words)
						return @expanded_key
				end
				protected :expand_key

				attr_reader :block
				def block=(new_block) #:nodoc:
					if(new_block.length != @current_block_length) then
						raise "Invalid block size: #{new_block.length}" unless(block_sizes_supported.find { |size| size==new_block.length })
						@current_block_length = new_block.length
						@block_words = @current_block_length / 4
						@expanded_key = nil
						@round_count = nil
					end
					@block = new_block
				end
				protected :block=, :block, :key

				# If you want to probe for supported block sizes, by all means use this method. It'll raise
				# if the value isn't supported.
				#
				# Don't use this: #block_sizes_supported is better.
        def blocksize=(block_size_bytes)
						self.block = "\x00" * block_size_bytes
						self
        end

				# This lets you know how big a block is currently being used.
				# There's probably no point using this.
        def blocksize
            return @block_words*4
        end

				# Provides a list of block sizes (bytes) which are supported
				def self.block_sizes_supported
					@@valid_blocksizes_bytes
				end

				# Provides a list of key sizes (bytes) which are supported
				def self.key_sizes_supported
					@@valid_keysizes_bytes
				end
        
				# This just calls the class' .block_sizes_supported method for you.
				def block_sizes_supported
					self.class.block_sizes_supported
				end
        
        
        def round_count #:nodoc:
						return @round_count if @round_count
						@round_count = Core.round_count(@block_words, @key_words)
        end
        

protected :round_count
        
=begin rdoc
Your main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.

The output is a Encrypted::ByteStream object, which is to say more-or-less a String.
=end
        def encrypt(plaintext)
						self.block = plaintext

            rounds=round_count
            expanded_key=expand_key
            
            blockl_b=@block_words*4
            #puts "m #{block.length}"
            tmp_block=Core.round0(block, expanded_key[0])
						tmp_block = Core.roundn_times(tmp_block, expanded_key, rounds, :forward)
            return Core.roundl(tmp_block, expanded_key[rounds])
        end
        
=begin rdoc
Your other main entry point. You must provide an input string of a valid length - if not, it'll +raise+.
Valid lengths are 16, 24 or 32 bytes, and it will pick the block size based on the length of the input.
Of course, if the string to decrypt is of invalid length then you've got other problems...

The output is a Encrypted::ByteStream object, which is to say more-or-less a String.
=end
        def decrypt(ciphertext)
						self.block = ciphertext
            rounds=round_count
            expanded_key=expand_key
            
            blockl_b=@block_words*4
            tmp_block=Core.inv_roundl(block, expanded_key[rounds])
						tmp_block = Core.roundn_times(tmp_block, expanded_key, rounds, :reverse)
            decrypted=Core.round0(tmp_block, expanded_key[0])
            #p "decrypted: #{decrypted}" if $VERBOSE
            return decrypted
        end
    end

=begin rdoc
This is exactly the same as Encrypted::Rijndael except that the only allowed block size is 128-bit (16 bytes
), which affects possible IV (for CBC and other block-chaining algorithms) and plaintext block lengths.

Given the effort that went into standardising on AES, you may well want to use this instead of 
Encrypted::Rijndael for encryption if you're interoperating with another party. Of course, you *can* safely
use Encrypted::Rijndael for decryption in that circumstance.

The spec for this is in an US government standards document named FIPS-197. Google for it.
=end
    class AES < Rijndael
        AES_BLOCKSIZE_BYTES=16

				# Only one block size is supported for real AES: 16 bytes.
				def self.block_sizes_supported
					[AES_BLOCKSIZE_BYTES]
				end
    end
end
