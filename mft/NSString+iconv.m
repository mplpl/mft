//
//  NSString+Iconv.m
//  MCModel
//
//  Created by Marcin Labenski on 13/11/2021.
//  Copyright © 2021 Marcin Labenski. All rights reserved.
//

#import "NSString+iconv.h"

@implementation NSString (iconv)

+ (NSString *)stringWithBuf:(const char *)s
                iconvToUtf8:(iconv_t)convBaseToUtf8 {
    
    if (s == 0) return nil;
    return [NSString stringWithBuf:s lenght:strlen(s) iconvToUtf8:convBaseToUtf8];
}

+ (NSString *)stringWithBuf:(const char *)s
                     lenght:(size_t)length
                iconvToUtf8:(iconv_t)convBaseToUtf8 {

    if (s == 0) return nil;
    if (length == 0 || *s == 0) return @"";
    
    if (convBaseToUtf8 == (iconv_t)-1) {
        return [NSString stringWithUTF8String:s];
    }
    
    size_t inSize = length;
    char outStr[inSize * 4 + 1];
    char *outPtr = outStr;
    size_t outSize = sizeof(outStr) - 1;
    char *inPtr = (char *)s;
    
    while (iconv(convBaseToUtf8, &inPtr, &inSize, &outPtr, &outSize) == (size_t)-1)
    {
        if (!outSize || !inSize) break;
        *outPtr = '?';
        outPtr++;
        outSize--;
        inPtr++;
        inSize--;
        if (!outSize || !inSize) break;
    }
    *outPtr = 0;
    return [NSString stringWithUTF8String:outStr];
}

- (const char *)toBuf:(char *)outBuf
            bufLenght:(size_t)outBufSize
        iconvFromUtf8:(iconv_t)convBaseFromUtf8 {
    
    if (outBufSize <= 0) {
        return nil;
    }
    
    if (self.length == 0 || outBufSize == 1) {
        *outBuf = 0;
        return outBuf;
    }
    
    const char * sUtf8 = self.UTF8String;
    if (convBaseFromUtf8 == (iconv_t)-1) {
        size_t ln = strlen(sUtf8);
        size_t op = (ln < outBufSize - 1) ? ln : (outBufSize - 1);
        strncpy(outBuf, sUtf8, op);
        outBuf[op] = 0;
        return outBuf;
    }
    
    char *outPtr = outBuf;
    size_t outSize = outBufSize - 1;
    char *inPtr = (char *)sUtf8;
    size_t inSize = strlen(sUtf8);
    
    while (iconv(convBaseFromUtf8, &inPtr, &inSize, &outPtr, &outSize) == (size_t)-1)
    {
        if (!outSize || !inSize) break;
        *outPtr = '?';
        outPtr++;
        outSize--;
        int chw = 1;
        unsigned char cp = (unsigned char)(*inPtr);
        if (cp < 0x80)
        {
            chw = 1;
        }
        else if (cp < 0xe0)
        {
            chw = 2;
        }
        else if (cp < 0xf0)
        {
            chw = 3;
        }
        else
        {
            chw = 4;
        }
        inPtr += chw;
        inSize -= chw;
        if (!outSize || !inSize) break;
    }
    *outPtr = 0;
    return outBuf;
}

- (size_t)convBufSize {
    return self.length * 4 + 1;
}
@end
