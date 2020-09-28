////
//  YFEncrypt.m
//
//  Created by Harry Phone on 2020/9/27.
//

#import "YFEncrypt.h"
#import "YFRSAEncrypt.h"
#import "YFHashEncrypt.h"
#import "YFSymmetricEncrypt.h"


@implementation NSString (YFEncrypt)

#pragma mark - public method
- (nullable NSData *)yf_base64Decode {
    return [[NSData alloc] initWithBase64EncodedString:self options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (NSString *)yf_md5String {
    return [self hashStringWithType:YFHashTypeMD5];
}

- (NSString *)yf_md5StringFor16Byte {
    return [[self yf_md5String] substringWithRange:NSMakeRange(8, 16)];
}

- (NSString *)yf_sha1String {
    return [self hashStringWithType:YFHashTypeSHA1];
}

- (NSString *)yf_sha224String {
    return [self hashStringWithType:YFHashTypeSHA224];
}

- (NSString *)yf_sha256String {
    return [self hashStringWithType:YFHashTypeSHA256];
}

- (NSString *)yf_sha384String {
    return [self hashStringWithType:YFHashTypeSHA384];
}

- (NSString *)yf_sha512String {
    return [self hashStringWithType:YFHashTypeSHA512];
}

- (nullable NSString *)yf_AESEncryptByKey:(NSString *)key {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] yf_AESEncryptByKey:key];
}

- (nullable NSData *)yf_AESDecryptByKey:(NSString *)key {
    return [[self yf_base64Decode] yf_AESDecryptByKey:key];
}

- (nullable NSString *)yf_RSAEncryptByKey:(NSString *)key {
    NSData *data = [self tryDecode];
    return [data yf_RSAEncryptByKey:key];
}

- (nullable NSData *)yf_RSADecryptByKey:(NSString *)key {
    NSData *data = [self yf_base64Decode];
    return [data yf_RSADecryptByKey:key];
}

#pragma mark - private method

/// 先base64的decode，不行在UTF8
- (nullable NSData*)tryDecode {
    NSData *data = [self yf_base64Decode];
    if (!data) {
        data = [self dataUsingEncoding:NSUTF8StringEncoding];
    }
    return data;
}

- (NSString *)hashStringWithType:(YFHashType)type {
    YFHashEncrypt *encryptor = [[YFHashEncrypt alloc] initWithType:type];
    encryptor.contentData = [self dataUsingEncoding:NSUTF8StringEncoding];
    return [encryptor getHashString];
}

@end

@implementation NSData (YFEncrypt)

#pragma mark - public method

- (NSString *)yf_base64Encode {
    return [[NSString alloc] initWithData:[self base64EncodedDataWithOptions:NSDataBase64EncodingEndLineWithLineFeed] encoding:NSUTF8StringEncoding];
}

+ (NSData *)yf_randomDataWithLength:(NSInteger)length {
    unsigned char buf[length];
    arc4random_buf(buf, length);
    return [NSData dataWithBytes:buf length:length];
}

- (NSString *)yf_md5String {
    return [self hashStringWithType:YFHashTypeMD5];
}

- (NSString *)yf_sha1String {
    return [self hashStringWithType:YFHashTypeSHA1];
}
- (NSString *)yf_sha224String {
    return [self hashStringWithType:YFHashTypeSHA224];
}
- (NSString *)yf_sha256String {
    return [self hashStringWithType:YFHashTypeSHA256];
}
- (NSString *)yf_sha384String {
    return [self hashStringWithType:YFHashTypeSHA384];
}
- (NSString *)yf_sha512String {
    return [self hashStringWithType:YFHashTypeSHA512];
}

- (nullable NSString *)yf_AESEncryptByKey:(NSString *)key {
    YFSymmetricEncrypt *encryptor = [[YFSymmetricEncrypt alloc] initWithType:YFSymmetricEncryptTypeAES];
    NSData *data = [encryptor operationData:self keyData:[key tryDecode] isEncrypt:YES];
    return [data yf_base64Encode];
}
- (nullable NSData *)yf_AESDecryptByKey:(NSString *)key {
    YFSymmetricEncrypt *encryptor = [[YFSymmetricEncrypt alloc] initWithType:YFSymmetricEncryptTypeAES];
    NSData *data = [encryptor operationData:self keyData:[key tryDecode] isEncrypt:NO];
    return data;
}

- (nullable NSString *)yf_RSAEncryptByKey:(NSString *)key {
    YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
    [encryptor loadPublicKey:key];
    return [encryptor encryptData:self isPublicKey:YES];
}
- (nullable NSData *)yf_RSADecryptByKey:(NSString *)key {
    YFRSAEncrypt *encryptor = [[YFRSAEncrypt alloc] init];
    [encryptor loadPublicKey:key];
    return [encryptor decryptData:self isPublicKey:YES];
}

#pragma mark - private method

- (NSString *)hashStringWithType:(YFHashType)type {
    YFHashEncrypt *encryptor = [[YFHashEncrypt alloc] initWithType:type];
    encryptor.contentData = self;
    return [encryptor getHashString];
}

@end
