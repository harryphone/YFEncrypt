////
//  YFSymmetricEncrypt.h
//
//  Created by Harry Phone on 2020/9/27.
//

#import <Foundation/Foundation.h>


/*
 对属性解释及理解：
 对称加密有一个块的概念，数据都是一块一块加解密的。
 不同类型的加密类型，块的长度大小是不同的，具体可以参考kCCBlockSizeAES128那块的枚举值
 
 iv：
 向量iv的长度与块的长度一致，短了会以0补齐，长了会被截断。
 使用iv的加密模式是CBC，所以iv有值是CBC模式，没有值是EBC模式。
 
 keyLength：
 不同类型的加密类型，秘钥的长度也是不一致的，具体可以参考kCCKeySizeAES128那块的枚举值
 AES有3种不同的固定的秘钥长度，分别为kCCKeySizeAES128、kCCKeySizeAES192、kCCKeySizeAES256
 DES、3DES只有1种固定的秘钥长度，分别是：kCCKeySizeDES、kCCKeySize3DES。
 CAST、RC4、RC2、Blowfish的秘钥长度是可变的，有最小值和最大值的限制，具体看枚举值中min和max
 keyLength会自动获取最接近的枚举值的长度，一般没有特殊需求，不用设置。

 isNoPadding：
 no-padding和zero-padding是一样的。
 ZeroPadding，数据长度不对齐时使用0填充，否则不填充。
 PKCS7Padding，假设数据长度需要填充n(n>0)个字节才对齐，那么填充n个字节，每个字节都是n;如果数据本身就已经对齐了，则填充一块长度为块大小的数据，每个字节都是块大小。
 PKCS5Padding，PKCS7Padding的子集，块大小固定为8字节。(iOS中并没有这个选项 = =!)
 由于使用PKCS7Padding/PKCS5Padding填充时，最后一个字节肯定为填充数据的长度，所以在解密后可以准确删除填充的数据，而使用ZeroPadding填充时，没办法区分真实数据与填充数据，所以只适合以\0结尾的字符串加解密。

 */


NS_ASSUME_NONNULL_BEGIN
typedef NS_ENUM(NSInteger, YFSymmetricEncryptType) {
    YFSymmetricEncryptTypeAES,
    YFSymmetricEncryptTypeDES,
    YFSymmetricEncryptType3DES,
    YFSymmetricEncryptTypeCAST,
    YFSymmetricEncryptTypeRC4,
    YFSymmetricEncryptTypeRC2,
    YFSymmetricEncryptTypeBlowfish,
};


@interface YFSymmetricEncrypt : NSObject

/// Default is AES
@property (nonatomic, assign) YFSymmetricEncryptType type;

/// The secret key length is automatically obtained based on the secret key data and is generally not required to be set
@property (nonatomic, assign) NSUInteger keyLength;

/// Offset vector, this property is CBC encryption mode if it has a value, otherwise ECB mode.
@property (nonatomic, copy, nullable) NSData *iv;

/// PKCS7Padding or NoPadding, Default is NO.
@property (nonatomic, assign) BOOL isNoPadding;

- (instancetype)initWithType:(YFSymmetricEncryptType)type NS_DESIGNATED_INITIALIZER;

/// Encryption and decryption method
/// @param data Data that needs to be encrypted or decrypted
/// @param keyData Data of key
/// @param isEncrypt Yes means encryption, and NO means decryption
- (nullable NSData *)operationData:(NSData *)data keyData:(NSData *)keyData isEncrypt:(BOOL)isEncrypt;

@end



@interface YFSymmetricEncrypt (Convenient)

/*
 封装的便利方法，应用在业务中
 秘钥通常是128或256位的随机Data，所以key为base64过的字符串表示。（如果key为utf8的，请用上方原始的方法，并记得设置keyLength）
 加密过后的数据是一串无序Data，并不能用utf8表示，所以会用base64过的string传给服务端
 需要解密的string应该也是base64的string，原因同上一条
 解密后数据并没有做处理，data可能会转成字符串，也可能直接转成字典或数组。
 */

/// Encryption methods, Result is in Base64 format
/// @param content Need to encrypt the content in UTF8 format
/// @param key Key is in Base64 format
- (nullable NSString *)encryptString:(NSString *)content withKey:(NSString *)key;

/// Decryption method
/// @param content Need to decrypt the content in Base64 format
/// @param key Key is in Base64 format
- (nullable NSData *)decryptString:(NSString *)content withKey:(NSString *)key;


@end

NS_ASSUME_NONNULL_END
