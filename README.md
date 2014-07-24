# Encrypted

Encryption and Decryption with Rijndael algorithm and CBC.

Key size options: 128, 192 and 254 bits
Block size options: 128, 192 and 254 bits


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'encrypted'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install encrypted

## Usage
Mode needs to be supplied when instantiating Encrypted::Ciph. Mode consists of desirable key length and block length in "keysize-blocksize" format.
"256-128" implies key size of 256 bits and block size of 128 bits.

### Encryption
```ruby
    encrypt_this = "This is seriously confidential message."
    cipher = Encrypted::Ciph.new("256-256")
    key = "xvxvxvxxvxvxvxvxvxvxvxvxvxvxvxvx" # 256 bits / 8 = 32 bytes
    iv = "nmnmnmnmnmnmnmnmnmnmjkjkhjhjhjgh"  # 256 bits / 8 = 32 bytes
    cipher.key = key
    cipher.iv = iv
    encrypted_text = cipher.encrypt(encrypt_this)
```
### Decryption
```ruby
    decrypt_this = encrypted_text               #from above
    decipher = Encrypted::Ciph.new("256-256")
    cipher.key = "xvxvxvxxvxvxvxvxvxvxvxvxvxvxvxvx"     #key used above to encrypt
    cipher.iv = "nmnmnmnmnmnmnmnmnmnmjkjkhjhjhjgh"      #initialization vector used above
    decrypted_text = cipher.decrypt(decrypt_this)
```
    "decrypted_text => 'This is some seriously confidential message.'"

### Key and IV generation helper
To automatically generate and assign right size of random key and iv bytes while encrypting. 
```ruby
    encrypt_this = "This is seriously confidential message. Let me generate stuff for ya."
    cipher = Encrypted::Ciph.new("256-128")
    key = cipher.generate_key                    # Sets and returns 32 bytes long string
    iv = cipher.generate_iv                      # Sets and returns 16 bytes long string
    encrypted_text = cipher.encrypt(encrypt_this)
    
```   

## Contributing

1. Fork it ( https://github.com/getaasciesh/encrypted/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
