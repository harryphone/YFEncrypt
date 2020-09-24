//
//  YFHashEncrypt.h
//  YFEncrypt
//
//  Created by harry phone on 2020/9/24.
//

#import <Foundation/Foundation.h>


typedef NS_ENUM(NSInteger, YFHashType) {
    YFHashTypeMD5,
    YFHashTypeSHA1,
    YFHashTypeSHA224,
    YFHashTypeSHA256,
    YFHashTypeSHA384,
    YFHashTypeSHA512,
};

NS_ASSUME_NONNULL_BEGIN

@interface YFHashEncrypt : NSObject

/// Hash type
@property (nonatomic, assign) YFHashType type;
/// HMAC will be used if keyData has a value
@property (nonatomic, copy, nullable) NSData *keyData;
/// Data that needs to be hashed, The contentData or filePath must have a value
@property (nonatomic, copy, nullable) NSData *contentData;
/// File that needs to be hashed, The contentData or filePath must have a value
@property (nonatomic, copy, nullable) NSString *filePath;

/// default is md5
/// @param type 散列类型
- (instancetype)initWithType:(YFHashType)type NS_DESIGNATED_INITIALIZER;

- (NSString *)getHashString;
- (NSData *)getHashData;

@end

NS_ASSUME_NONNULL_END
