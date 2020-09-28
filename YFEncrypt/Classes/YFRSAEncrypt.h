////
//  YFRSAEncrypt.h
//
//  Created by Harry Phone on 2020/9/27.
//


#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, YFRSAEncryptPaddingType) {
    YFRSAEncryptPaddingTypeNone,
    YFRSAEncryptPaddingTypePKCS1,
    YFRSAEncryptPaddingTypeOAEP,
};

typedef NS_ENUM(NSInteger, YFRSASignType) {
    YFRSASignTypeSHA1,
    YFRSASignTypeSHA224,
    YFRSASignTypeSHA256,
    YFRSASignTypeSHA384,
    YFRSASignTypeSHA512,
};

@interface YFRSAEncrypt : NSObject

/// default YFRSAEncryptPaddingTypePKCS1
@property (nonatomic, assign) YFRSAEncryptPaddingType encryptPaddingType;
/// default YFRSASignTypeSHA1
@property (nonatomic, assign) YFRSASignType signType;

/// Generate key pairs
/// @param keySize Key size, optional value(512/768/1024/2048)
- (void)generateKeyPair:(NSUInteger)keySize;

// Load the public key
- (void)loadPublicKey:(NSString *)key;
- (void)loadPublicData:(NSData *)keyData;

// Load the private key
- (void)loadPrivateKey:(NSString *)key;
- (void)loadPrivateData:(NSData *)keyData;

// Read the public key from the X509 DER certificate
- (void)loadDerFile:(NSString *)filePath;

// Load the private key from P12
- (void)loadP12File:(NSString *)filePath password:(NSString *)pwd;

// Load the secret key from PEM
- (void)loadPublicKeyFromPemFile:(NSString *)filePath keySize:(size_t )size;
- (void)loadPrivateKeyFromPemFile:(NSString *)filePath keySize:(size_t )size;

// To obtain the public key
- (nullable NSString *)getPublicKey;
- (nullable NSData *)getPublicData;

// Access to the private key
- (nullable NSString *)getPrivateKey;
- (nullable NSData *)getPrivateData;

/// Encryption methods, Result is in Base64 format
/// @param data Data need to encrypt
/// @param isPublic YES use publicKey, NO use privateKey
- (nullable NSString *)encryptData:(NSData *)data isPublicKey:(BOOL)isPublic;

/// Decryption method
/// @param string String is in Base64 format
/// @param isPublic YES use publicKey, NO use privateKey
- (nullable NSData *)decryptString:(NSString *)string isPublicKey:(BOOL)isPublic;

/// Decryption method
/// @param data data content
/// @param isPublic YES use publicKey, NO use privateKey
- (nullable NSData *)decryptData:(NSData *)data isPublicKey:(BOOL)isPublic;


/// Signature of data
/// @param data Data need to sign
/// @param isPublic YES use publicKey, NO use privateKey
- (nullable NSString *)signData:(NSData *)data isPublicKey:(BOOL)isPublic;

/// Signature of file
/// @param filePath path of file
/// @param isPublic YES use publicKey, NO use privateKey
- (nullable NSString *)signFile:(NSString *)filePath isPublicKey:(BOOL)isPublic;


/// Verify the signature of the data
/// @param data Data need to verify
/// @param signString Signature string
/// @param isPublic YES use publicKey, NO use privateKey
- (BOOL)verifyData:(NSData *)data signString:(NSString *)signString isPublicKey:(BOOL)isPublic;

/// Verify the signature of the file
/// @param filePath path of file
/// @param signString Signature string
/// @param isPublic YES use publicKey, NO use privateKey
- (BOOL)verifyFile:(NSString *)filePath signString:(NSString *)signString isPublicKey:(BOOL)isPublic;


// Save to the keychain or load from the keychain
- (void)savePublicKeyWithName:(NSString *)name;
- (void)savePrivateKeyWithName:(NSString *)name;
- (void)loadPublicKeyWithName:(NSString *)name;
- (void)loadPrivateKeyWithName:(NSString *)name;

@end

NS_ASSUME_NONNULL_END
