//
//  NSString+Iconv.h
//  MCModel
//
//  Created by Marcin Labenski on 13/11/2021.
//  Copyright © 2021 Marcin Labenski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <iconv.h>

@interface NSString (iconv)

+ (NSString *)stringWithBuf:(const char *)s
                iconvToUtf8:(iconv_t)convBaseToUtf8;

+ (NSString *)stringWithBuf:(const char *)s
                     lenght:(size_t)length
                iconvToUtf8:(iconv_t)convBaseToUtf8;

- (const char *)toBuf:(char *)outBuf
            bufLenght:(size_t)outBufSize
        iconvFromUtf8:(iconv_t)convBaseFromUtf8;

- (size_t)convBufSize;

@end

