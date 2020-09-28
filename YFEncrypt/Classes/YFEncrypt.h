////
//  YFEncrypt.h
//
//  Created by Harry Phone on 2020/9/27.
//

#import <Foundation/Foundation.h>

/**
 本类中的key，优先进行Base64转换，转换失败才会进行utf8的转换。如果key是纯字母加数字的，并且是utf8格式的，请直接调用相应的加密类
 
 In this class, Base64 conversion is preferred, UTF8 conversion is performed only if the Base64 conversion fails. If the key is pure alphabetic and numeric and is in UTF8 format, call the corresponding encryption class directly
 */

NS_ASSUME_NONNULL_BEGIN

@interface NSString (YFEncrypt)

/// base64 string to data
- (nullable NSData *)yf_base64Decode;

- (NSString *)yf_md5String;
- (NSString *)yf_md5StringFor16Byte;
- (NSString *)yf_sha1String;
- (NSString *)yf_sha224String;
- (NSString *)yf_sha256String;
- (NSString *)yf_sha384String;
- (NSString *)yf_sha512String;

- (nullable NSString *)yf_AESEncryptByKey:(NSString *)key;
- (nullable NSData *)yf_AESDecryptByKey:(NSString *)key;

- (nullable NSString *)yf_RSAEncryptByKey:(NSString *)key;
- (nullable NSData *)yf_RSADecryptByKey:(NSString *)key;

@end

@interface NSData (YFEncrypt)

/// data to base64 string
- (NSString *)yf_base64Encode;

/// 随机生成指定长度的data
/// @param length data的长度，比如生成aes128的秘钥，传16.
+ (NSData *)yf_randomDataWithLength:(NSInteger)length;

- (NSString *)yf_md5String;
- (NSString *)yf_sha1String;
- (NSString *)yf_sha224String;
- (NSString *)yf_sha256String;
- (NSString *)yf_sha384String;
- (NSString *)yf_sha512String;

- (nullable NSString *)yf_AESEncryptByKey:(NSString *)key;
- (nullable NSData *)yf_AESDecryptByKey:(NSString *)key;

- (nullable NSString *)yf_RSAEncryptByKey:(NSString *)key;
- (nullable NSData *)yf_RSADecryptByKey:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
