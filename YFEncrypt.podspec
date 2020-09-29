#
# Be sure to run `pod lib lint YFEncrypt.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'YFEncrypt'
  s.version          = '0.1.0'
  s.summary          = 'The encapsulation of hashing, symmetric encryption, and asymmetric encryption'


  s.description      = <<-DESC
  The encapsulation of hashing, symmetric encryption, and asymmetric encryption.
  Hash: MD5, SHA1, SHA224, SHA256, SHA384, SHA512
  Symmetric: AES, DES, 3DES, CAST, RC4, RC2, Blowfish
  Asymmetric: RSA
                       DESC

  s.homepage         = 'https://github.com/harryphone/YFEncrypt'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'harryphone@163.com' => 'harryphone@163.com' }
  s.source           = { :git => 'https://github.com/harryphone/YFEncrypt.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '10.0'

  s.source_files = 'YFEncrypt/Classes/**/*'
  
end
