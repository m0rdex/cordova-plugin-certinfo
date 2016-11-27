#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface CertInfo : CDVPlugin

- (void)check:(CDVInvokedUrlCommand*)command;

@end
