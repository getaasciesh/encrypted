# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'encrypted/version'

Gem::Specification.new do |spec|
  spec.name          = "encrypted"
  spec.version       = Encrypted::VERSION
  spec.authors       = ["asish bhattarai"]
  spec.email         = ["getaasciesh@hotmail.com"]
  spec.summary       = %q{Rijndael encryption with cbc.}
  spec.description   = %q{Rijndael encryption with cbc. More Coming soon.}
  spec.homepage      = "https://github.com/getaasciesh/encrypted"
  spec.license       = "LICENCE.txt"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake", "~> 10.0"
end
