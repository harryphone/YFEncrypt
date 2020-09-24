//
//  YFHashEncrypt.m
//  YFEncrypt
//
//  Created harry phone on 2020/9/24.
//

#import "YFHashEncrypt.h"
#import <CommonCrypto/CommonCrypto.h>

#define FileHashDefaultChunkSizeForReadingData 4096

@implementation YFHashEncrypt

#pragma mark - Public Method

- (instancetype)init {
    
    return [self initWithType:YFHashTypeMD5];
}

- (instancetype)initWithType:(YFHashType)type {
    self = [super init];
    if (self) {
        _type = type;
    }
    return self;
}

- (NSData *)getHashData {
    if ([self.filePath isKindOfClass:[NSString class]]) {
        if ([self.keyData isKindOfClass:[NSData class]]) {
            return [self fileHmacHashData];
        } else {
            return [self fileHashData];
        }
    } else if ([self.contentData isKindOfClass:[NSData class]]) {
        if ([self.keyData isKindOfClass:[NSData class]]) {
            return [self hmacHashData];
        } else {
            return [self hashData];
        }
    } else {
        NSAssert(NO, @"The contentData or filePath must have a right value");
        return [NSData data];
    }
}

- (NSString *)getHashString {
    NSData *data = [self getHashData];
    if (data.length == 0) {
        return @"";
    }
    const uint8_t *buffer = data.bytes;
    NSMutableString *strM = [NSMutableString string];
    for (int i = 0; i < data.length; i++) {
        [strM appendFormat:@"%02x", buffer[i]];
    }
    return [strM copy];
}

#pragma mark - Private Method

- (NSData *)hashData {
    
    switch (self.type) {
        case YFHashTypeMD5: {
            uint8_t buffer[CC_MD5_DIGEST_LENGTH];
            CC_MD5(self.contentData.bytes, (CC_LONG)self.contentData.length, buffer);
            return [NSData dataWithBytes:buffer length:CC_MD5_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA1: {
            uint8_t buffer[CC_SHA1_DIGEST_LENGTH];
            CC_SHA1(self.contentData.bytes, (CC_LONG)self.contentData.length, buffer);
            return [NSData dataWithBytes:buffer length:CC_SHA1_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA224: {
            uint8_t buffer[CC_SHA224_DIGEST_LENGTH];
            CC_SHA224(self.contentData.bytes, (CC_LONG)self.contentData.length, buffer);
            return [NSData dataWithBytes:buffer length:CC_SHA224_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA256: {
            uint8_t buffer[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(self.contentData.bytes, (CC_LONG)self.contentData.length, buffer);
            return [NSData dataWithBytes:buffer length:CC_SHA256_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA384: {
            uint8_t buffer[CC_SHA384_DIGEST_LENGTH];
            CC_SHA384(self.contentData.bytes, (CC_LONG)self.contentData.length, buffer);
            return [NSData dataWithBytes:buffer length:CC_SHA384_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA512: {
            uint8_t buffer[CC_SHA512_DIGEST_LENGTH];
            CC_SHA512(self.contentData.bytes, (CC_LONG)self.contentData.length, buffer);
            return [NSData dataWithBytes:buffer length:CC_SHA512_DIGEST_LENGTH];
        }
            break;
            
        default:{
            NSAssert(NO, @"There is no such hash type");
            return [NSData data];
        }
            break;
    }
}

- (NSData *)hmacHashData {
    CCHmacAlgorithm algorithm = 0;
    size_t length = 0;
    switch (self.type) {
        case YFHashTypeMD5:
            algorithm = kCCHmacAlgMD5;
            length = CC_MD5_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA1:
            algorithm = kCCHmacAlgSHA1;
            length = CC_SHA1_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA224:
            algorithm = kCCHmacAlgSHA224;
            length = CC_SHA224_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA256:
            algorithm = kCCHmacAlgSHA256;
            length = CC_SHA256_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA384:
            algorithm = kCCHmacAlgSHA384;
            length = CC_SHA384_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA512:
            algorithm = kCCHmacAlgSHA512;
            length = CC_SHA512_DIGEST_LENGTH;
            break;
        default:
            NSAssert(NO, @"There is no such hash type");
            return [NSData data];
    }
    uint8_t buffer[length];
    CCHmac(algorithm, self.keyData.bytes, self.keyData.length, self.contentData.bytes, self.contentData.length, buffer);
    return [NSData dataWithBytes:buffer length:length];
}

- (NSData *)fileHashData {
    NSFileHandle *fp = [NSFileHandle fileHandleForReadingAtPath:self.filePath];
    if (fp == nil) {
        NSAssert(NO, @"file path error");
        return [NSData data];
    }
    NSData *result = [NSData data];
    switch (self.type) {
        case YFHashTypeMD5: {
            CC_MD5_CTX hashCtx;
            CC_MD5_Init(&hashCtx);
            while (YES) {
                @autoreleasepool {
                    NSData *data = [fp readDataOfLength:FileHashDefaultChunkSizeForReadingData];
                    CC_MD5_Update(&hashCtx, data.bytes, (CC_LONG)data.length);
                    if (data.length == 0) {
                        break;
                    }
                }
            }
            uint8_t buffer[CC_MD5_DIGEST_LENGTH];
            CC_MD5_Final(buffer, &hashCtx);
            result = [NSData dataWithBytes:buffer length:CC_MD5_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA1: {
            CC_SHA1_CTX hashCtx;
            CC_SHA1_Init(&hashCtx);
            while (YES) {
                @autoreleasepool {
                    NSData *data = [fp readDataOfLength:FileHashDefaultChunkSizeForReadingData];
                    CC_SHA1_Update(&hashCtx, data.bytes, (CC_LONG)data.length);
                    if (data.length == 0) {
                        break;
                    }
                }
            }
            uint8_t buffer[CC_SHA1_DIGEST_LENGTH];
            CC_SHA1_Final(buffer, &hashCtx);
            result = [NSData dataWithBytes:buffer length:CC_SHA1_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA224: {
            CC_SHA256_CTX hashCtx;
            CC_SHA224_Init(&hashCtx);
            while (YES) {
                @autoreleasepool {
                    NSData *data = [fp readDataOfLength:FileHashDefaultChunkSizeForReadingData];
                    CC_SHA224_Update(&hashCtx, data.bytes, (CC_LONG)data.length);
                    if (data.length == 0) {
                        break;
                    }
                }
            }
            uint8_t buffer[CC_SHA224_DIGEST_LENGTH];
            CC_SHA224_Final(buffer, &hashCtx);
            result = [NSData dataWithBytes:buffer length:CC_SHA224_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA256: {
            CC_SHA256_CTX hashCtx;
            CC_SHA256_Init(&hashCtx);
            while (YES) {
                @autoreleasepool {
                    NSData *data = [fp readDataOfLength:FileHashDefaultChunkSizeForReadingData];
                    CC_SHA256_Update(&hashCtx, data.bytes, (CC_LONG)data.length);
                    if (data.length == 0) {
                        break;
                    }
                }
            }
            uint8_t buffer[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256_Final(buffer, &hashCtx);
            result = [NSData dataWithBytes:buffer length:CC_SHA256_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA384: {
            CC_SHA512_CTX hashCtx;
            CC_SHA384_Init(&hashCtx);
            while (YES) {
                @autoreleasepool {
                    NSData *data = [fp readDataOfLength:FileHashDefaultChunkSizeForReadingData];
                    CC_SHA384_Update(&hashCtx, data.bytes, (CC_LONG)data.length);
                    if (data.length == 0) {
                        break;
                    }
                }
            }
            uint8_t buffer[CC_SHA384_DIGEST_LENGTH];
            CC_SHA384_Final(buffer, &hashCtx);
            result = [NSData dataWithBytes:buffer length:CC_SHA384_DIGEST_LENGTH];
        }
            break;
        case YFHashTypeSHA512: {
            CC_SHA512_CTX hashCtx;
            CC_SHA512_Init(&hashCtx);
            while (YES) {
                @autoreleasepool {
                    NSData *data = [fp readDataOfLength:FileHashDefaultChunkSizeForReadingData];
                    CC_SHA512_Update(&hashCtx, data.bytes, (CC_LONG)data.length);
                    if (data.length == 0) {
                        break;
                    }
                }
            }
            uint8_t buffer[CC_SHA512_DIGEST_LENGTH];
            CC_SHA512_Final(buffer, &hashCtx);
            result = [NSData dataWithBytes:buffer length:CC_SHA512_DIGEST_LENGTH];
        }
            break;
            
        default:
            NSAssert(NO, @"There is no such hash type");
            return [NSData data];
    }
    [fp closeFile];
    return result;
}

- (NSData *)fileHmacHashData {
    NSFileHandle *fp = [NSFileHandle fileHandleForReadingAtPath:self.filePath];
    if (fp == nil) {
        NSAssert(NO, @"file path error");
        return [NSData data];
    }
    CCHmacAlgorithm algorithm = 0;
    size_t length = 0;
    switch (self.type) {
        case YFHashTypeMD5:
            algorithm = kCCHmacAlgMD5;
            length = CC_MD5_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA1:
            algorithm = kCCHmacAlgSHA1;
            length = CC_SHA1_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA224:
            algorithm = kCCHmacAlgSHA224;
            length = CC_SHA224_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA256:
            algorithm = kCCHmacAlgSHA256;
            length = CC_SHA256_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA384:
            algorithm = kCCHmacAlgSHA384;
            length = CC_SHA384_DIGEST_LENGTH;
            break;
        case YFHashTypeSHA512:
            algorithm = kCCHmacAlgSHA512;
            length = CC_SHA512_DIGEST_LENGTH;
            break;
        default:
            NSAssert(NO, @"There is no such hash type");
            return [NSData data];
    }
    CCHmacContext hashContext;
    CCHmacInit(&hashContext, algorithm, self.keyData.bytes, self.keyData.length);
    while (YES) {
        @autoreleasepool {
            NSData *data = [fp readDataOfLength:FileHashDefaultChunkSizeForReadingData];
            CCHmacUpdate(&hashContext, data.bytes, data.length);
            if (data.length == 0) {
                break;
            }
        }
    }
    [fp closeFile];
    uint8_t buffer[length];
    CCHmacFinal(&hashContext, buffer);
    return [NSData dataWithBytes:buffer length:length];
   
}

@end
