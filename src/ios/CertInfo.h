#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface CertInfo : CDVPlugin

- (void)fetch:(CDVInvokedUrlCommand*)command;

@end
