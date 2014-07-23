require "encrypted/version"
require "encrypted/rijndael"
require "encrypted/cbc"
module Encrypted
  class Ciph
    attr_accessor :key, :iv
    MODE_KEYS = [128,192,256]

    def initialize(mode)
      decode_mode mode
    end

    def key=(word)
      if (@key_length/8 == word.bytesize)
        @key = word
      else
        raise 'Key length mismatched with encryption mode'
      end
    end

    def iv=(word)
      if (@iv_length/8 == word.bytesize)
        @iv = word
      else
        raise 'Iv length mismatched with encryption mode'
      end
    end

    def decode_mode(mode)
      mode_array = mode.split('-')
      key_length = mode_array[0].to_i if mode_array[0]
      iv_length = mode_array[1].to_i if mode_array[1]
      if (MODE_KEYS.include? key_length) && (MODE_KEYS.include? iv_length)
        @key_length = key_length
        @iv_length = iv_length
      else
        raise "Mode '#{mode}' is invalid. Please provide one of these #{self.class.modes}"
      end
    end

    def self.modes
      modes_array = []
      MODE_KEYS.each do |k|
        a_mode = "'"+k.to_s
        MODE_KEYS.each {|kk| modes_array << a_mode + '-'+ kk.to_s + "'"}
      end
      modes_array.join(', ')
    end

    def generate_iv
      @iv = SecureRandom.random_bytes(@iv_length/8)
    end

    def generate_key
      @key = SecureRandom.random_bytes(@key_length/8)
    end

    def encrypt(plain_text)
      raise "Cannot encrypt without key and/or iv" unless @key && @iv
      cipher = Encrypted::Rijndael.new(@key)
      cbc = Encrypted::CBC.new(cipher)
      cbc.encrypt(@iv, plain_text)
    end

    def decrypt(encrypted_text)
      raise "Cannot decrypt without key and/or iv" unless @key && @iv
      cipher = Encrypted::Rijndael.new(@key)
      cbc = Encrypted::CBC.new(cipher)
      cbc.decrypt(@iv, encrypted_text)
    end

  end
end
