//
//  NSData+SHAES.h
//  SmartHomeSDK
//
//  Created by JQ on 2017/8/11.
//  Copyright © 2017年 JQ. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (SHAES)

#pragma mark -明文密钥，密钥可以用明文字符串表示
/**
 加密方法
 
 @param key 明文密钥 密钥长度16位
 @return 加密后的Data
 */
- (NSData *)sh_AESEncryptWithKey:(NSString *)key;

/**
 解密方法
 
 @param key 明文密钥，密钥长度16位
 @return 解密后的Data
 */
- (NSData *)sh_AESDecryptWithKey:(NSString *)key;



#pragma mark -base64密钥，密钥可能无法解析为字符串，用Base64编码转换为字符串
/**
 加密方法
 
 @param base64Key Base64编码的密钥
 @return 加密后的Data
 */
- (NSData *)sh_AESEncryptWithBase64Key:(NSString *)base64Key;

/**
 解密方法
 
 @param base64Key Base64编码的密钥
 @return 解密后的Data
 */
- (NSData *)sh_AESDecryptWithBase64Key:(NSString *)base64Key;



#pragma mark -data类型密钥
/**
 加密方法

 @param dataKey 16个字节的密钥
 @return 加密后的Data
 */
- (NSData *)sh_AESEncryptWithDataKey:(NSData *)dataKey;

/**
 解密方法

 @param dataKey 16个字节的密钥
 @return 解密后的Data
 */
- (NSData *)sh_AESDecryptWithDataKey:(NSData *)dataKey;


@end
