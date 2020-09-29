# YFEncrypt

[![CI Status](https://img.shields.io/travis/harryphone@163.com/YFEncrypt.svg?style=flat)](https://travis-ci.org/harryphone@163.com/YFEncrypt)
[![Version](https://img.shields.io/cocoapods/v/YFEncrypt.svg?style=flat)](https://cocoapods.org/pods/YFEncrypt)
[![License](https://img.shields.io/cocoapods/l/YFEncrypt.svg?style=flat)](https://cocoapods.org/pods/YFEncrypt)
[![Platform](https://img.shields.io/cocoapods/p/YFEncrypt.svg?style=flat)](https://cocoapods.org/pods/YFEncrypt)

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

## Requirements

Minimum iOS Target is iOS 10.

## Installation

YFEncrypt is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'YFEncrypt'
```

## Usage

### Hash

#### MD5

```objective-c
NSLog(@"%@", [@"hello, world!" yf_md5String]);
```

#### Hmac SHA512

```objective-c
YFHashEncrypt *encryptor = [[YFHashEncrypt alloc] initWithType:YFHashTypeSHA512];
encryptor.contentData = [@"hello, world!" dataUsingEncoding:NSUTF8StringEncoding];
encryptor.keyData = [@"hmac key" dataUsingEncoding:NSUTF8StringEncoding];
NSString *result = [encryptor getHashString];
NSLog(@"result: %@", result);
```
#### File SHA256

```objective-c
NSString *filePath = [[NSBundle mainBundle] pathForResource:@"private" ofType:@"pem"];
YFHashEncrypt *encryptor = [[YFHashEncrypt alloc] initWithType:YFHashTypeSHA256];
encryptor.filePath = filePath;
NSString *fileResult = [encryptor getHashString];
NSLog(@"fileResult: %@", fileResult);
```

### Symmetric Encrypt

```objective-c
// random key
NSData *aes256KeyData = [NSData yf_randomDataWithLength:32];
NSString *aesKey = [aes256KeyData yf_base64Encode];
NSLog(@"aesKey: %@", aesKey);

NSString *testString = @"hello, world!";
YFSymmetricEncrypt *encryptor = [[YFSymmetricEncrypt alloc] initWithType:YFSymmetricEncryptTypeAES];

// encryption
NSData *resultData = [encryptor operationData:[testString dataUsingEncoding:NSUTF8StringEncoding] keyData:aes256KeyData isEncrypt:YES];
NSLog(@"encryptResult: %@", [resultData yf_base64Encode]);

NSString *result = [encryptor encryptString:testString withKey:aesKey];
NSLog(@"encryptResult: %@", result);

result = [testString yf_AESEncryptByKey:aesKey];
NSLog(@"encryptResult: %@", result);

// decryption
NSData *decryptData = [encryptor operationData:resultData keyData:aes256KeyData isEncrypt:NO];
NSLog(@"decryptResult: %@", [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding]);

decryptData = [encryptor decryptString:result withKey:aesKey];
NSLog(@"decryptResult: %@", [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding]);

decryptData = [result yf_AESDecryptByKey:aesKey];
NSLog(@"decryptResult: %@", [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding]);
```

### RSA

#### Get Key String And Encryption

```objective-c
- (void)verifyRSAEncrypt:(YFRSAEncrypt *)encryptor {
    NSLog(@"public key: %@", [encryptor getPublicKey]);
    NSLog(@"private key: %@", [encryptor getPrivateKey]);
    
    NSString *result = [encryptor encryptData:[@"hello" dataUsingEncoding:NSUTF8StringEncoding] isPublicKey:YES];
    NSLog(@"encryptResult: %@", result);
    
    NSData *decryptData = [encryptor decryptString:result isPublicKey:NO];
    NSLog(@"decryptResult: %@", [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding]);
}
```

#### Load P12 And Der File

```objective-c
YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
NSString *filePath = [[NSBundle mainBundle] pathForResource:@"p" ofType:@"p12"];
[encryptor loadP12File:filePath password:@"123456"];

filePath = [[NSBundle mainBundle] pathForResource:@"rsacert" ofType:@"der"];
[encryptor loadDerFile:filePath];

[self verifyRSAEncrypt:encryptor];
```

#### Load Key String

```objective-c
NSString *privateKey = @"-----BEGIN RSA PRIVATE KEY-----MIICXgIBAAKBgQDKM1liWihMQvCSme8KOgYJk7LoU/pzih1V6137ual1M4UxGmVLHYxiQ4P7DP8bwIAxN0D+NEFeDUi1lcDvzlQR83P8h6JzT777YwRDUPf7EAeTiwrV80UP2w01mO5DLCScszQ8Y9cJV76wJEAJI4Jf/SyX90So1j1y6gbvDDNi7wIDAQABAoGAEZFQjMkEg0u1lyckq6DK8X4RpznUosE3N0XRzpMc8//b7J48esBAeDEhgGhqqcCZ4qzISs3DeCZzUMOIFc25ZAZX5BVpBVdLYxHRvSgoIZIxy+IQ0Xy69ARFwYWsWTfxlXpC8VUPiU1FkNsKRjvUxL+IpOuDAsDyTByboS4MLjECQQDkpMaOi5qg7YSWxAXXNRE/ihu06CYWzl8VQ6TtrjLXnK+03aZIZIj4h7in1nWExRlSBR6IyGiIvvAxuvz5hipzAkEA4mSjKpXHUHXR6/TBCDm1d3+faDkBzEIk5KPO6zBJr349kW1aq6N9ulqRq5G2mApPjpZTB3Do0DCAynjTJ78alQJBAK82jmpCFTbpjUez4/3tTtBwV5ckp7umXjr/YW46pf+QtR1XFcw4Lra12w3TTK94E1VFUwbi/Sh9mbeiYaYd6H0CQQCNvD/C+36LSxgfx13Kjoajx8y+7WHIxWhflIaJC/Q14K0fDP2FE5g1QVqNtW5BhcMFG+vjbrbzEEqxeC+KZMR5AkEAqpIHukvTttU5EsR/wYm0+C11kIevsLRsiGZ7Me/JB2KjmmtOCMxxF/Vm+uwlL4j4xBO+LsaIRfHCtmB6l/YtXA==-----END RSA PRIVATE KEY-----";
NSString *publicKey = @"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKM1liWihMQvCSme8KOgYJk7LoU/pzih1V6137ual1M4UxGmVLHYxiQ4P7DP8bwIAxN0D+NEFeDUi1lcDvzlQR83P8h6JzT777YwRDUPf7EAeTiwrV80UP2w01mO5DLCScszQ8Y9cJV76wJEAJI4Jf/SyX90So1j1y6gbvDDNi7wIDAQAB-----END PUBLIC KEY-----";

YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
[encryptor loadPublicKey:publicKey];
[encryptor loadPrivateKey:privateKey];

[self verifyRSAEncrypt:encryptor];
```

#### Load Pem File

```objective-c
YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];

NSString *filePath = [[NSBundle mainBundle] pathForResource:@"private" ofType:@"pem"];
[encryptor loadPrivateKeyFromPemFile:filePath];

filePath = [[NSBundle mainBundle] pathForResource:@"public" ofType:@"pem"];
[encryptor loadPublicKeyFromPemFile:filePath];

[self verifyRSAEncrypt:encryptor];
```

#### Generate Key Pair

```objective-c
YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
[encryptor generateKeyPair:1024];

[self verifyRSAEncrypt:encryptor];
```

## Author

harryphone@163.com

## License

YFEncrypt is available under the MIT license. See the LICENSE file for more info.
