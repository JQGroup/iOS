//
//  NSData+SHAES.m
//  SmartHomeSDK
//
//  Created by JQ on 2017/8/11.
//  Copyright © 2017年 JQ. All rights reserved.
//

#import "NSData+SHAES.h"
#import <CommonCrypto/CommonCryptor.h>
#import "GTMBase64.h"
#import "NSData+Base64.h"

@implementation NSData (SHAES)

#pragma mark -明文密钥，密钥可以用明文字符串表示

#pragma mark -加密方法
- (NSData *)sh_AESEncryptWithKey:(NSString *)key
{
    NSData *encryptData = [self sh_AES128Operation:kCCEncrypt key:key iv:nil];
    return encryptData;
}

#pragma mark -解密方法
- (NSData *)sh_AESDecryptWithKey:(NSString *)key
{
    NSData *decryptData = [self sh_AES128Operation:kCCDecrypt key:key iv:nil];
    return decryptData;
}

- (NSData *)sh_AES128Operation:(CCOperation)operation key:(NSString *)key iv:(NSString *)iv
{
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128 + 1024;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionECBMode | kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSData *data = [NSData dataWithBytes:buffer length:numBytesCrypted];
        free(buffer);
        return [NSData dataWithData:data];
    }
    return nil;
}


#pragma mark -base64密钥，密钥可能无法解析为字符串，用Base64编码转换为字符串

#pragma mark -加密方法
- (NSData *)sh_AESEncryptWithBase64Key:(NSString *)base64Key
{
    NSData *encryptData = [self sh_AES128Operation:kCCEncrypt base64Key:base64Key iv:nil];
    return encryptData;
}

#pragma mark -解密方法
- (NSData *)sh_AESDecryptWithBase64Key:(NSString *)base64Key
{
    NSData *decryptData = [self sh_AES128Operation:kCCDecrypt base64Key:base64Key iv:nil];
    return decryptData;
}

- (NSData *)sh_AES128Operation:(CCOperation)operation base64Key:(NSString *)base64Key iv:(NSString *)iv
{
    NSData *keyData = [NSData dataWithBase64EncodedString:base64Key];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128 + 1024;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionECBMode | kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSData *data = [NSData dataWithBytes:buffer length:numBytesCrypted];
        free(buffer);
        return [NSData dataWithData:data];
    }
    return nil;
}

#pragma mark -data类型密钥

#pragma mark -加密方法
- (NSData *)sh_AESEncryptWithDataKey:(NSData *)dataKey
{
    NSData *encryptData = [self sh_AES128Operation:kCCEncrypt dataKey:dataKey iv:nil];
    return encryptData;
}

#pragma mark -解密方法
- (NSData *)sh_AESDecryptWithDataKey:(NSData *)dataKey
{
    NSData *decryptData = [self sh_AES128Operation:kCCDecrypt dataKey:dataKey iv:nil];
    return decryptData;
}

- (NSData *)sh_AES128Operation:(CCOperation)operation dataKey:(NSData *)dataKey iv:(NSString *)iv
{
    NSData *keyData = dataKey;
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128 + 1024;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,
                                          kCCOptionECBMode | kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSData *data = [NSData dataWithBytes:buffer length:numBytesCrypted];
        free(buffer);
        return [NSData dataWithData:data];
    }
    return nil;
}

@end
