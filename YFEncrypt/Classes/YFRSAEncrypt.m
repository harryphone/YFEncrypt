////
//  YFRSAEncrypt.m
//
//  Created by Harry Phone on 2020/9/27.
//

#import "YFRSAEncrypt.h"
#import "YFHashEncrypt.h"

@interface YFRSAEncrypt () {
    SecKeyRef publicKeyRef;   // 公钥引用
    SecKeyRef privateKeyRef;    // 私钥引用
}

@property (nonatomic, strong) NSData *publicTag;   // 公钥标签
@property (nonatomic, strong) NSData *privateTag;  // 私钥标签



@end

@implementation YFRSAEncrypt

#pragma mark - life cycle

- (instancetype)init {
    self = [super init];
    if (self) {
        _encryptPaddingType = YFRSAEncryptPaddingTypePKCS1;
        _signType = YFRSASignTypeSHA1;
        
        publicKeyRef = NULL;
        privateKeyRef = NULL;
        
        NSUInteger length = 4;
        unsigned char buf[length];
        arc4random_buf(buf, length);
        NSData *preData = [NSData dataWithBytes:buf length:length];
        NSMutableData *publicData = preData.mutableCopy;
        NSMutableData *privateData = preData.mutableCopy;
        [publicData appendData:[@"public" dataUsingEncoding:NSUTF8StringEncoding]];
        [privateData appendData:[@"private" dataUsingEncoding:NSUTF8StringEncoding]];
        _publicTag = [publicData copy];
        _privateTag = [privateData copy];
        
        }
    return self;
}

- (void)dealloc {
    [self clearAllKeyRef];
}

#pragma mark - load the private or public key

- (void)loadPublicKey:(NSString *)key {
    key = [self getContentOfKey:key diffTitle:@"PUBLIC"];
    NSData *data = [self decodeBase64String:key];
    if (data) {
        [self loadPublicData:data];
    } else {
        NSAssert(NO, @"key error");
    }
}

- (void)loadPublicData:(NSData *)keyData {
    [self clearPublicKeyRef];
    
    NSMutableDictionary *dickey = [[NSMutableDictionary alloc] initWithCapacity:2];
    [dickey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [dickey setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    
    NSError *error = nil;
    CFErrorRef ee = (__bridge CFErrorRef)error;
    publicKeyRef = SecKeyCreateWithData((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)dickey, &ee);
    
    if (ee) {
        publicKeyRef = NULL;
        NSAssert(NO, @"failed to load public key");
    } else {
        [self addKeyRef:publicKeyRef withTag:self.publicTag];
    }
}

- (void)loadPrivateKey:(NSString *)key {
    key = [self getContentOfKey:key diffTitle:@"PRIVATE"];
    NSData *data = [self decodeBase64String:key];
    if (data) {
        [self loadPrivateData:data];
    } else {
        NSAssert(NO, @"key error");
    }
}

- (void)loadPrivateData:(NSData *)keyData {
    [self clearPrivateKeyRef];
    
    NSMutableDictionary *dickey = [[NSMutableDictionary alloc] initWithCapacity:2];
    [dickey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [dickey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    
    NSError *error = nil;
    CFErrorRef ee = (__bridge CFErrorRef)error;
    privateKeyRef = SecKeyCreateWithData((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)dickey, &ee);
    
    if (ee) {
        privateKeyRef = NULL;
        NSAssert(NO, @"failed to load private key");
    } else {
        [self addKeyRef:privateKeyRef withTag:self.privateTag];
    }
}

- (void)loadDerFile:(NSString *)filePath {
    
    NSAssert(filePath.length != 0, @"filePath is empty");
    
    [self clearPublicKeyRef];
    
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    SecCertificateRef certificateRef = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
    NSAssert(certificateRef != NULL, @"der file error");
    
    // 返回一个默认 X509 策略的公钥对象，使用之后需要调用 CFRelease 释放
    SecPolicyRef policyRef = SecPolicyCreateBasicX509();
    // 包含信任管理信息的结构体
    SecTrustRef trustRef;
    
    // 基于证书和策略创建一个信任管理对象
    OSStatus status = SecTrustCreateWithCertificates(certificateRef, policyRef, &trustRef);
    NSAssert(status == errSecSuccess, @"Failed to create trust management object");
    
    // 信任结果
    SecTrustResultType trustResult;
    // 评估指定证书和策略的信任管理是否有效
    status = SecTrustEvaluate(trustRef, &trustResult);
    NSAssert(status == errSecSuccess, @"Failure of trust assessment");
    
    // 评估之后返回公钥子证书
    publicKeyRef = SecTrustCopyPublicKey(trustRef);
    [self addKeyRef:publicKeyRef withTag:self.publicTag];
    NSAssert(publicKeyRef != NULL, @"Public key creation failed");
    
    if (certificateRef) CFRelease(certificateRef);
    if (policyRef) CFRelease(policyRef);
    if (trustRef) CFRelease(trustRef);
}

- (void)loadP12File:(NSString *)filePath password:(NSString *)pwd {
    
    NSAssert(filePath.length != 0, @"filePath is empty");
    
    // 删除当前私钥
    [self clearPrivateKeyRef];
    
    NSData *PKCS12Data = [NSData dataWithContentsOfFile:filePath];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)pwd;
    
    // 从 PKCS #12 证书中提取标示和证书
    SecIdentityRef myIdentity = NULL;
    SecTrustRef myTrust = NULL;
    const void *keys[] =   {kSecImportExportPassphrase};
    const void *values[] = {passwordRef};
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    // 返回 PKCS #12 格式数据中的标示和证书
    OSStatus status = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);
    
    if (status == noErr) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        myIdentity = (SecIdentityRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        myTrust = (SecTrustRef)CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
    }
    
    
    NSAssert(status == noErr, @"Failed to extract identity and trust");
    
    SecTrustResultType trustResult;
    // 评估指定证书和策略的信任管理是否有效
    status = SecTrustEvaluate(myTrust, &trustResult);
    NSAssert(status == errSecSuccess, @"Failure of trust assessment");
    
    // 提取私钥
    status = SecIdentityCopyPrivateKey(myIdentity, &privateKeyRef);
    NSAssert(status == errSecSuccess, @"Private key creation failed");
    [self addKeyRef:privateKeyRef withTag:self.privateTag];
    
    if (optionsDictionary) CFRelease(optionsDictionary);
    if (items) CFRelease(items);
}

- (void)loadPublicKeyFromPemFile:(NSString *)filePath {
    [self clearPublicKeyRef];
    
    NSError *readFErr = nil;
    NSString *pemStr = [NSString stringWithContentsOfFile:filePath encoding:NSASCIIStringEncoding error:&readFErr];
    NSAssert(readFErr == nil, @"Pem file path is error");
    
    [self loadPublicKey:pemStr];
    
}

- (void)loadPrivateKeyFromPemFile:(NSString *)filePath {
    [self clearPrivateKeyRef];
    
    NSError *readFErr = nil;
    NSString *pemStr = [NSString stringWithContentsOfFile:filePath encoding:NSASCIIStringEncoding error:&readFErr];
    NSAssert(readFErr == nil, @"Pem file path is error");
    
    [self loadPrivateKey:pemStr];
   
}

#pragma mark - Generate secret key pairs
- (void)generateKeyPair:(NSUInteger)keySize {
    
    NSAssert1((keySize == 512 || keySize == 768 || keySize == 1024 || keySize == 2048), @"Invalid key size %tu", keySize);
    
    // 删除当前密钥对
    [self clearAllKeyRef];
    
    OSStatus sanityCheck = noErr;
    
    // 容器字典
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // 设置密钥对的顶级字典
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:@(keySize) forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // 设置私钥字典
    [privateKeyAttr setObject:@(YES) forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    // 设置公钥字典
    [publicKeyAttr setObject:@(YES) forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    // 设置顶级字典属性
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair 返回密钥对引用
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    NSAssert((sanityCheck == noErr && publicKeyRef != NULL && privateKeyRef != NULL), @"Failed to generate the key pair");
}

#pragma mark - 获取秘钥

// 获取公钥
- (NSString *)getPublicKey {
    return [self base64EncodeData:[self getPublicData]];
}

- (NSData *)getPublicData {
    return [self getKeyBitsWithTag:self.publicTag];
}

// 获取私钥
- (NSString *)getPrivateKey {
    return [self base64EncodeData:[self getPrivateData]];
}

- (NSData *)getPrivateData {
    return [self getKeyBitsWithTag:self.privateTag];
}

#pragma mark - 保存或加载到钥匙串

- (void)savePublicKeyWithName:(NSString *)name {
    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    [self addKeyRef:publicKeyRef withTag:nameData];
}

- (void)savePrivateKeyWithName:(NSString *)name {
    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    [self addKeyRef:privateKeyRef withTag:nameData];
}

- (void)loadPublicKeyWithName:(NSString *)name {
    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    [self clearPublicKeyRef];
    publicKeyRef = [self getKeyRefWithTag:nameData];
    [self addKeyRef:publicKeyRef withTag:self.publicTag];
}

- (void)loadPrivateKeyWithName:(NSString *)name {
    NSData *nameData = [name dataUsingEncoding:NSUTF8StringEncoding];
    [self clearPrivateKeyRef];
    privateKeyRef = [self getKeyRefWithTag:nameData];
    [self addKeyRef:privateKeyRef withTag:self.privateTag];
}

#pragma mark - encryption and decryption

- (nullable NSString *)encryptData:(NSData *)data isPublicKey:(BOOL)isPublic {
    NSData *resultData = [self encryptData:data withKeyRef:(isPublic ? publicKeyRef : privateKeyRef)];
    return [self base64EncodeData:resultData];
}

- (nullable NSData *)decryptString:(NSString *)string isPublicKey:(BOOL)isPublic {
    return [self decryptData:[self decodeBase64String:string] withKeyRef:(isPublic ? publicKeyRef : privateKeyRef)];
}

- (nullable NSData *)decryptData:(NSData *)data isPublicKey:(BOOL)isPublic {
    return [self decryptData:data withKeyRef:(isPublic ? publicKeyRef : privateKeyRef)];
}

#pragma mark - signature and signature check
// 签名，需要设置signType
- (nullable NSString *)signData:(NSData *)data isPublicKey:(BOOL)isPublic {
    YFHashEncrypt *hasher = [[YFHashEncrypt alloc] init];
    switch (self.signType) {
        case YFRSASignTypeSHA1:
            hasher.type = YFHashTypeSHA1;
            break;
        case YFRSASignTypeSHA224:
            hasher.type = YFHashTypeSHA224;
            break;
        case YFRSASignTypeSHA256:
            hasher.type = YFHashTypeSHA256;
            break;
        case YFRSASignTypeSHA384:
            hasher.type = YFHashTypeSHA384;
            break;
        case YFRSASignTypeSHA512:
            hasher.type = YFHashTypeSHA512;
            break;
        default:
            NSAssert(NO, @"unknown sign type");
            return nil;
            break;
    }
    hasher.contentData = data;
    NSData *resultData = [self signHashData:[hasher getHashData] withKeyRef:(isPublic ? publicKeyRef : privateKeyRef)];
    return [self base64EncodeData:resultData];
}

- (nullable NSString *)signFile:(NSString *)filePath isPublicKey:(BOOL)isPublic {
    YFHashEncrypt *hasher = [[YFHashEncrypt alloc] init];
    switch (self.signType) {
        case YFRSASignTypeSHA1:
            hasher.type = YFHashTypeSHA1;
            break;
        case YFRSASignTypeSHA224:
            hasher.type = YFHashTypeSHA224;
            break;
        case YFRSASignTypeSHA256:
            hasher.type = YFHashTypeSHA256;
            break;
        case YFRSASignTypeSHA384:
            hasher.type = YFHashTypeSHA384;
            break;
        case YFRSASignTypeSHA512:
            hasher.type = YFHashTypeSHA512;
            break;
        default:
            NSAssert(NO, @"unknown sign type");
            return nil;
            break;
    }
    hasher.filePath = filePath;
    NSData *resultData = [self signHashData:[hasher getHashData] withKeyRef:(isPublic ? publicKeyRef : privateKeyRef)];
    return [self base64EncodeData:resultData];
}

// 验签
- (BOOL)verifyData:(NSData *)data signString:(NSString *)signString isPublicKey:(BOOL)isPublic {
    YFHashEncrypt *hasher = [[YFHashEncrypt alloc] init];
    switch (self.signType) {
        case YFRSASignTypeSHA1:
            hasher.type = YFHashTypeSHA1;
            break;
        case YFRSASignTypeSHA224:
            hasher.type = YFHashTypeSHA224;
            break;
        case YFRSASignTypeSHA256:
            hasher.type = YFHashTypeSHA256;
            break;
        case YFRSASignTypeSHA384:
            hasher.type = YFHashTypeSHA384;
            break;
        case YFRSASignTypeSHA512:
            hasher.type = YFHashTypeSHA512;
            break;
        default:
            NSAssert(NO, @"unknown sign type");
            return NO;
            break;
    }
    hasher.contentData = data;
    return [self verifyHashData:[hasher getHashData] withKeyRef:(isPublic ? publicKeyRef : privateKeyRef) signature:[self decodeBase64String:signString]];
}

- (BOOL)verifyFile:(NSString *)filePath signString:(NSString *)signString isPublicKey:(BOOL)isPublic {
    YFHashEncrypt *hasher = [[YFHashEncrypt alloc] init];
    switch (self.signType) {
        case YFRSASignTypeSHA1:
            hasher.type = YFHashTypeSHA1;
            break;
        case YFRSASignTypeSHA224:
            hasher.type = YFHashTypeSHA224;
            break;
        case YFRSASignTypeSHA256:
            hasher.type = YFHashTypeSHA256;
            break;
        case YFRSASignTypeSHA384:
            hasher.type = YFHashTypeSHA384;
            break;
        case YFRSASignTypeSHA512:
            hasher.type = YFHashTypeSHA512;
            break;
        default:
            NSAssert(NO, @"unknown sign type");
            return NO;
            break;
    }
    hasher.filePath = filePath;
    return [self verifyHashData:[hasher getHashData] withKeyRef:(isPublic ? publicKeyRef : privateKeyRef) signature:[self decodeBase64String:signString]];
    
}

#pragma mark - private method

- (NSString *)base64EncodeData:(NSData *)data {
    data = [data base64EncodedDataWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

- (NSData *)decodeBase64String:(NSString *)string {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

- (void)clearAllKeyRef {
    [self clearPrivateKeyRef];
    [self clearPublicKeyRef];
}

- (void)clearPublicKeyRef {
    if (publicKeyRef) {
        CFRelease(publicKeyRef);
        [self deleteKeyRefWithTag:self.publicTag];
    }
    publicKeyRef = NULL;
}

- (void)clearPrivateKeyRef {
    if (privateKeyRef) {
        CFRelease(privateKeyRef);
        [self deleteKeyRefWithTag:self.privateTag];
    }
    privateKeyRef = NULL;
}

//获取证书data
- (NSData *)getKeyBitsWithTag:(NSData *)tag {
    OSStatus sanityCheck = noErr;
    NSData * keyBits = nil;
    CFTypeRef pk;
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryKey setObject:@(YES) forKey:(__bridge id)kSecReturnData];
    
    // Get the key bits.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, &pk);
    
    if (sanityCheck != noErr)
    {
        pk = nil;
    }
    keyBits = (__bridge_transfer NSData*)pk;
    return keyBits;
}

- (NSData *)addKeyRef:(SecKeyRef)keyRef withTag:(NSData *)tag {
    OSStatus sanityCheck = noErr;
    NSData * keyBits = nil;
    CFTypeRef result;
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    [queryKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryKey setObject:@(YES) forKey:(__bridge id)kSecReturnData];
    [queryKey setObject:(__bridge id)keyRef forKey:(__bridge id)kSecValueRef];
    
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) queryKey, &result);
    if (sanityCheck == errSecSuccess) {
        keyBits = CFBridgingRelease(result);
    } else {
        NSLog(@"YFRSAEncrypt: Failed to add keyRef");
    }
    return keyBits;
}

- (SecKeyRef)addKeyData:(NSData *)keyData withTag:(NSData *)tag {
    OSStatus sanityCheck = noErr;
    SecKeyRef keyReference = NULL;
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    [queryKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryKey setObject:@(YES) forKey:(__bridge id)kSecReturnRef];
    [queryKey setObject:keyData forKey:(__bridge id)kSecValueData];
    
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) queryKey, (CFTypeRef *)&keyReference);
    
    if (sanityCheck != errSecSuccess) {
        keyReference = NULL;
        NSLog(@"YFRSAEncrypt: Failed to add keyData");
    }
    
    return keyReference;
}

- (void)deleteKeyRefWithTag:(NSData *)tag {
    OSStatus sanityCheck = noErr;
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    [queryKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef) queryKey);
    
    if (sanityCheck != errSecSuccess) {
        NSLog(@"YFRSAEncrypt: Failed to delete KeyRef");
    }
}

- (void)updateKeyRef:(SecKeyRef)keyRef withTag:(NSData *)tag {
    OSStatus sanityCheck = noErr;
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    [queryKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    NSMutableDictionary * updateKey = queryKey.mutableCopy;
    [updateKey setObject:(__bridge id)keyRef forKey:(__bridge id)kSecValueRef];
    
    sanityCheck = SecItemUpdate((__bridge CFDictionaryRef) queryKey, (__bridge CFDictionaryRef) updateKey);
    
    if (sanityCheck != errSecSuccess) {
        NSLog(@"YFRSAEncrypt: Failed to update KeyRef");
    }
}

- (SecKeyRef)getKeyRefWithTag:(NSData *)tag {
    OSStatus sanityCheck = noErr;
    SecKeyRef keyReference = NULL;
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    [queryKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryKey setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryKey setObject:@(YES) forKey:(__bridge id)kSecReturnRef];
    
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&keyReference);
    
    if (sanityCheck != noErr) {
        keyReference = NULL;
        NSLog(@"YFRSAEncrypt: Failed to get KeyRef");
    }
    
    return keyReference;
}

- (NSString *)getContentOfKey:(NSString *)key diffTitle:(NSString *)title {
    NSRange spos;
    NSRange epos;
    spos = [key rangeOfString:[NSString stringWithFormat:@"-----BEGIN RSA %@ KEY-----", title]];
    if(spos.length > 0){
        epos = [key rangeOfString:[NSString stringWithFormat:@"-----END RSA %@ KEY-----", title]];
    }else{
        spos = [key rangeOfString:[NSString stringWithFormat:@"-----BEGIN %@ KEY-----", title]];
        epos = [key rangeOfString:[NSString stringWithFormat:@"-----END %@ KEY-----", title]];
    }
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    return key;
}

- (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef {
    if (!keyRef || data.length <1) {
        return nil;
    }
    size_t blockSize = SecKeyGetBlockSize(keyRef);
    
    SecPadding rsaPdd;
    size_t maxLength  = 0;
    switch (self.encryptPaddingType) {
        case YFRSAEncryptPaddingTypeNone:
            rsaPdd = kSecPaddingNone;
            maxLength = blockSize;
            break;
        case YFRSAEncryptPaddingTypePKCS1:
            rsaPdd = kSecPaddingPKCS1;
            maxLength = blockSize - 11;
            break;
        case YFRSAEncryptPaddingTypeOAEP:
            rsaPdd = kSecPaddingOAEP;
            maxLength = blockSize - 42;
            break;
        default:
            return nil;
            break;
    }
    
    NSMutableData *retData = [[NSMutableData alloc] init];
    uint8_t *encData = malloc(blockSize);
    const uint8_t *buffer = data.bytes;
    
    for (int i = 0; i < data.length; i += maxLength) {
        bzero(encData, blockSize);
        size_t dataLength = MIN(maxLength, data.length - i);
        size_t outlen = blockSize;
        OSStatus ret = SecKeyEncrypt(keyRef, rsaPdd, buffer+i, dataLength, encData, &outlen);
        if (ret == errSecSuccess) {
            [retData appendBytes:encData length:outlen];
        } else {
            NSLog(@"YFRSAEncrypt: Failed to encrypt");
            retData = nil;
            break;
        }
    }
    
    if (encData) { free(encData); }
    
    return retData;
}

- (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef {
    if (!keyRef || data.length <1) {
        return nil;
    }
    size_t blockSize = SecKeyGetBlockSize(keyRef);
    
    SecPadding rsaPdd;
    switch (self.encryptPaddingType) {
        case YFRSAEncryptPaddingTypeNone:
            rsaPdd = kSecPaddingNone;
            break;
        case YFRSAEncryptPaddingTypePKCS1:
            rsaPdd = kSecPaddingPKCS1;
            break;
        case YFRSAEncryptPaddingTypeOAEP:
            rsaPdd = kSecPaddingOAEP;
            break;
        default:
            return nil;
            break;
    }
        
    NSMutableData *retData = [[NSMutableData alloc] init];
    uint8_t *decData = malloc(blockSize);
    const uint8_t *buffer = data.bytes;
    
    for (int i = 0; i < data.length; i += blockSize) {
        bzero(decData, blockSize);
        size_t dataLength = MIN(blockSize, data.length - i);
        size_t outlen = blockSize;
        OSStatus ret = SecKeyDecrypt(keyRef, rsaPdd, buffer+i, dataLength, decData, &outlen);
        if (ret == errSecSuccess) {
            [retData appendBytes:decData length:outlen];
        } else {
            NSLog(@"YFRSAEncrypt: Failed to decrypt");
            retData = nil;
            break;
        }
    }
    
    if (decData) { free(decData); }
    
    return retData;
}

- (NSData *)signHashData:(NSData *)hashData withKeyRef:(SecKeyRef)keyRef {
    if (!keyRef || hashData.length < 1) {
        return nil;
    }
    
    OSStatus ret;
    NSData *retData = nil;
    size_t siglen = SecKeyGetBlockSize(keyRef);
    
    SecPadding secpdal ;
    switch (self.signType) {
        case YFRSASignTypeSHA1:
            secpdal = kSecPaddingPKCS1SHA1;
            break;
        case YFRSASignTypeSHA224:
            secpdal = kSecPaddingPKCS1SHA224;
            break;
        case YFRSASignTypeSHA256:
            secpdal = kSecPaddingPKCS1SHA256;
            break;
        case YFRSASignTypeSHA384:
            secpdal = kSecPaddingPKCS1SHA384;
            break;
        case YFRSASignTypeSHA512:
            secpdal = kSecPaddingPKCS1SHA512;
            break;
        default:
            return nil;
            break;
    }
    
    uint8_t *sig = malloc(siglen);
    bzero(sig, siglen);
    
    ret = SecKeyRawSign(keyRef, secpdal, hashData.bytes, hashData.length, sig, &siglen);
    if (ret == errSecSuccess) {
        retData = [NSData dataWithBytes:sig length:siglen];
    }
    
    if (sig) free(sig);
    
    return retData;
}

- (BOOL)verifyHashData:(NSData *)hashData withKeyRef:(SecKeyRef)keyRef signature:(NSData *)signData {
    size_t signedHashBytesSize = 0;
    OSStatus sanityCheck = noErr;
    
    signedHashBytesSize = SecKeyGetBlockSize(keyRef);
    
    SecPadding secpdal ;
    switch (self.signType) {
        case YFRSASignTypeSHA1:
            secpdal = kSecPaddingPKCS1SHA1;
            break;
        case YFRSASignTypeSHA224:
            secpdal = kSecPaddingPKCS1SHA224;
            break;
        case YFRSASignTypeSHA256:
            secpdal = kSecPaddingPKCS1SHA256;
            break;
        case YFRSASignTypeSHA384:
            secpdal = kSecPaddingPKCS1SHA384;
            break;
        case YFRSASignTypeSHA512:
            secpdal = kSecPaddingPKCS1SHA512;
            break;
        default:
            return NO;
            break;
    }
    
    sanityCheck = SecKeyRawVerify(keyRef, secpdal, hashData.bytes, hashData.length, signData.bytes, signedHashBytesSize);
    
    return (sanityCheck == noErr) ? YES : NO;
}

@end
