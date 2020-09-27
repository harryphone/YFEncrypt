//
//  YFHashEncrypt.h
//  YFEncrypt
//
//  Created by harry phone on 2020/9/24.
//

#import <Foundation/Foundation.h>

/*
 属性的中文解释：
 
 keyData：
 如果有值，将使用hmac模式。不使用string的原因是，并不清楚秘钥是utf8的，还是base64的。所以交给使用者自己处理。
 
 filePath：
 需要hash的文件路径。如果文件过大，转成data再hash的话，可能会造成内存暴涨，所以边读边hash，里面加了@autoreleasepool，会及时的释放临时变量。
 
 contentData：
 需要hash的数据。filePath和contentData只需要设置一个，如果都有值，只会处理filePath的内容。
 
 */


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
- (instancetype)initWithType:(YFHashType)type NS_DESIGNATED_INITIALIZER;

- (NSString *)getHashString;
- (NSData *)getHashData;

@end

NS_ASSUME_NONNULL_END
