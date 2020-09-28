//
//  YFViewController.m
//  YFEncrypt
//
//  Created by harryphone@163.com on 09/24/2020.
//  Copyright (c) 2020 harryphone@163.com. All rights reserved.
//

#import "YFViewController.h"
#import <YFEncrypt/YFEncrypt.h>
#import <YFEncrypt/YFRSAEncrypt.h>
#import <YFEncrypt/YFHashEncrypt.h>
#import <YFEncrypt/YFSymmetricEncrypt.h>

@interface YFViewController ()

@end

@implementation YFViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	
//    [self MD5Test];
//    [self fileSHA256Test];
//    [self hmacSHA512Test];
//    [self AESTest];
//    [self generateRSAKeyPairTest];
//    [self loadPemFileTest];
    [self RSAEncryptTest];
//    [self loadP12AndCerFileTest];
}

- (void)loadP12AndCerFileTest {
    YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"p" ofType:@"p12"];
    [encryptor loadP12File:filePath password:@"123456"];
    filePath = [[NSBundle mainBundle] pathForResource:@"rsacert" ofType:@"der"];
    [encryptor loadDerFile:filePath];

    [self verifyRSAEncrypt:encryptor];
}

- (void)RSAEncryptTest {
    NSString *privateKey = @"-----BEGIN RSA PRIVATE KEY-----MIICXgIBAAKBgQDKM1liWihMQvCSme8KOgYJk7LoU/pzih1V6137ual1M4UxGmVLHYxiQ4P7DP8bwIAxN0D+NEFeDUi1lcDvzlQR83P8h6JzT777YwRDUPf7EAeTiwrV80UP2w01mO5DLCScszQ8Y9cJV76wJEAJI4Jf/SyX90So1j1y6gbvDDNi7wIDAQABAoGAEZFQjMkEg0u1lyckq6DK8X4RpznUosE3N0XRzpMc8//b7J48esBAeDEhgGhqqcCZ4qzISs3DeCZzUMOIFc25ZAZX5BVpBVdLYxHRvSgoIZIxy+IQ0Xy69ARFwYWsWTfxlXpC8VUPiU1FkNsKRjvUxL+IpOuDAsDyTByboS4MLjECQQDkpMaOi5qg7YSWxAXXNRE/ihu06CYWzl8VQ6TtrjLXnK+03aZIZIj4h7in1nWExRlSBR6IyGiIvvAxuvz5hipzAkEA4mSjKpXHUHXR6/TBCDm1d3+faDkBzEIk5KPO6zBJr349kW1aq6N9ulqRq5G2mApPjpZTB3Do0DCAynjTJ78alQJBAK82jmpCFTbpjUez4/3tTtBwV5ckp7umXjr/YW46pf+QtR1XFcw4Lra12w3TTK94E1VFUwbi/Sh9mbeiYaYd6H0CQQCNvD/C+36LSxgfx13Kjoajx8y+7WHIxWhflIaJC/Q14K0fDP2FE5g1QVqNtW5BhcMFG+vjbrbzEEqxeC+KZMR5AkEAqpIHukvTttU5EsR/wYm0+C11kIevsLRsiGZ7Me/JB2KjmmtOCMxxF/Vm+uwlL4j4xBO+LsaIRfHCtmB6l/YtXA==-----END RSA PRIVATE KEY-----";
    NSString *publicKey = @"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKM1liWihMQvCSme8KOgYJk7LoU/pzih1V6137ual1M4UxGmVLHYxiQ4P7DP8bwIAxN0D+NEFeDUi1lcDvzlQR83P8h6JzT777YwRDUPf7EAeTiwrV80UP2w01mO5DLCScszQ8Y9cJV76wJEAJI4Jf/SyX90So1j1y6gbvDDNi7wIDAQAB-----END PUBLIC KEY-----";
    YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
    [encryptor loadPublicKey:publicKey];
    [encryptor loadPrivateKey:privateKey];
    
    [self verifyRSAEncrypt:encryptor];
}

- (void)loadPemFileTest {
    YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"private" ofType:@"pem"];
    [encryptor loadPrivateKeyFromPemFile:filePath];
    filePath = [[NSBundle mainBundle] pathForResource:@"public" ofType:@"pem"];
    [encryptor loadPublicKeyFromPemFile:filePath];

    [self verifyRSAEncrypt:encryptor];
}

- (void)generateRSAKeyPairTest {
    YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
    [encryptor generateKeyPair:1024];
    
    [self verifyRSAEncrypt:encryptor];
}

- (void)verifyRSAEncrypt:(YFRSAEncrypt *)encryptor {
    NSLog(@"public key: %@", [encryptor getPublicKey]);
    NSLog(@"private key: %@", [encryptor getPrivateKey]);
    
    NSString *result = [encryptor encryptData:[@"hello" dataUsingEncoding:NSUTF8StringEncoding] isPublicKey:YES];
    NSLog(@"encryptResult: %@", result);
    NSData *decryptData = [encryptor decryptString:result isPublicKey:NO];
    NSLog(@"decryptResult: %@", [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding]);
}

- (void)MD5Test {
    NSLog(@"%@", [@"hello, world!" yf_md5String]);
}

- (void)fileSHA256Test {
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"private" ofType:@"pem"];
    
    YFHashEncrypt *encryptor = [[YFHashEncrypt alloc] initWithType:YFHashTypeSHA256];
    encryptor.filePath = filePath;
    NSString *fileResult = [encryptor getHashString];
    NSLog(@"fileResult: %@", fileResult);
    
    NSData *fileData = [[NSData alloc] initWithContentsOfFile:filePath];
    encryptor.filePath = nil;
    encryptor.contentData = fileData;
    NSString *dataResult = [encryptor getHashString];
    NSLog(@"dataResult: %@", dataResult);
    
    if ([dataResult isEqualToString:fileResult]) {
        NSLog(@"hash值一致");
    } else {
        NSLog(@"hash值不一致");
    }
    
}

- (void)hmacSHA512Test {
    YFHashEncrypt *encryptor = [[YFHashEncrypt alloc] initWithType:YFHashTypeSHA512];
    encryptor.contentData = [@"hello, world!" dataUsingEncoding:NSUTF8StringEncoding];
    encryptor.keyData = [@"hmac key" dataUsingEncoding:NSUTF8StringEncoding];
    NSString *result = [encryptor getHashString];
    NSLog(@"result: %@", result);
}

- (void)AESTest {
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
}

@end
