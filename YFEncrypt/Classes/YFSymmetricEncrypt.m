////
//  YFSymmetricEncrypt.m
//
//  Created by Harry Phone on 2020/9/27.
//

#import "YFSymmetricEncrypt.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation YFSymmetricEncrypt

- (instancetype)init {
    return [self initWithType:YFSymmetricEncryptTypeAES];
}

- (instancetype)initWithType:(YFSymmetricEncryptType)type {
    self = [super init];
    if (self) {
        _type = type;
        _keyLength = 0;
        _iv = nil;
        _isNoPadding = NO;
    }
    return self;
}

- (NSData *)operationData:(NSData *)data keyData:(NSData *)keyData isEncrypt:(BOOL)isEncrypt {
    if (data.length == 0 || keyData.length == 0) {
        NSLog(@"YFSymmetricEncrypt: The encrypted content or secret key is empty");
        return nil;
    }
    
    CCAlgorithm algorithm;
    size_t blockSize;
    size_t keySize = keyData.length;

    switch (self.type) {
        case YFSymmetricEncryptTypeAES:
            algorithm = kCCAlgorithmAES128;
            blockSize = kCCBlockSizeAES128;
            if (keySize <= kCCKeySizeAES128) {
                keySize = kCCKeySizeAES128;
            } else if (keySize <= kCCKeySizeAES192) {
                keySize = kCCKeySizeAES192;
            } else {
                keySize = kCCKeySizeAES256;
            }
            break;
        case YFSymmetricEncryptTypeDES:
            algorithm = kCCAlgorithmDES;
            blockSize = kCCBlockSizeDES;
            keySize = kCCKeySizeDES;
            break;
        case YFSymmetricEncryptType3DES:
            algorithm = kCCAlgorithm3DES;
            blockSize = kCCBlockSize3DES;
            keySize = kCCKeySize3DES;
            break;
        case YFSymmetricEncryptTypeCAST:
            algorithm = kCCAlgorithmCAST;
            blockSize = kCCBlockSizeCAST;
            keySize = MIN(MAX(keySize, kCCKeySizeMinCAST), kCCKeySizeMaxCAST);
            break;
        case YFSymmetricEncryptTypeRC4:
            algorithm = kCCAlgorithmRC4;
            blockSize = kCCBlockSizeRC2;
            keySize = MIN(MAX(keySize, kCCKeySizeMinRC4), kCCKeySizeMaxRC4);
            break;
        case YFSymmetricEncryptTypeRC2:
            algorithm = kCCAlgorithmRC2;
            blockSize = kCCBlockSizeRC2;
            keySize = MIN(MAX(keySize, kCCKeySizeMinRC2), kCCKeySizeMaxRC2);
            break;
        case YFSymmetricEncryptTypeBlowfish:
            algorithm = kCCAlgorithmBlowfish;
            blockSize = kCCBlockSizeBlowfish;
            keySize = MIN(MAX(keySize, kCCKeySizeMinBlowfish), kCCKeySizeMaxBlowfish);
            break;
        default:
            NSAssert(NO, @"Unknown encryption type");
            return nil;
            break;
    }
    
    if (self.keyLength != 0) {
        keySize = self.keyLength;
    }
    
    unsigned char cKey[keySize];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:keySize];
    
    // setup iv
    uint8_t cIv[blockSize];
    bzero(cIv, blockSize);
    
    // setup option
    CCOptions option = 0;
    if (!self.isNoPadding) {
        option |= kCCOptionPKCS7Padding;
    }
    if (self.iv) {
        [self.iv getBytes:cIv length:blockSize];
    } else {
        option |= kCCOptionECBMode;
    }
    
    // setup output buffer
    size_t bufferSize = [data length] + blockSize;
    void *buffer = malloc(bufferSize);
    
    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(isEncrypt ? kCCEncrypt : kCCDecrypt,
                                          algorithm,
                                          option,
                                          cKey,
                                          keySize,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    
    NSData* result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {
        free(buffer);
        NSLog(@"YFSymmetricEncrypt errorStatus: %d", cryptStatus);
    }
    
    return result;
}

@end


@implementation YFSymmetricEncrypt (Convenient)

- (nullable NSString *)encryptString:(NSString *)content withKey:(NSString *)key {
    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *result = [self operationData:contentData keyData:keyData isEncrypt:YES];
    result = [result base64EncodedDataWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

- (nullable NSData *)decryptString:(NSString *)content withKey:(NSString *)key {
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [self operationData:contentData keyData:keyData isEncrypt:NO];
}

@end
