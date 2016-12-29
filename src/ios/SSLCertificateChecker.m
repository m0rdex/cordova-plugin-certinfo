#import "SSLCertificateChecker.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject <NSURLConnectionDelegate>;

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (nonatomic, assign) BOOL _allowUntrusted;
@property (nonatomic, assign) BOOL sentResponse;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId allowUntrusted:(BOOL)allowUntrusted;

@end

@implementation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId allowUntrusted:(BOOL)allowUntrusted;
{
    self.sentResponse = FALSE;
    self._plugin = plugin;
    self._callbackId = callbackId;
    self._allowUntrusted = allowUntrusted;
    return self;
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge {
    SecTrustRef trustRef = [[challenge protectionSpace] serverTrust];
    SecTrustResultType trustResult;
    SecTrustEvaluate(trustRef, &trustResult);

    [connection cancel];

    BOOL trusted = kSecTrustResultProceed == trustResult || kSecTrustResultUnspecified == trustResult;
    SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, 0);
    NSData* certData = (NSData*) CFBridgingRelease(SecCertificateCopyData(certRef));

    if (certData == NULL || !trusted && !self._allowUntrusted) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_NOT_SECURE"];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
        return;
    }

    NSString* data = [certData base64EncodedStringWithOptions:0];
    NSString* subject = [[NSString alloc] initWithString:(NSString*)
                         CFBridgingRelease(SecCertificateCopySubjectSummary(certRef))];
    NSString* fingerprint = [self getFingerprint:certData];

    NSDictionary* dict = @{
                           @"trusted" : @(trusted),
                           @"certificate" : data,
                           @"fingerprint" : fingerprint,
                           @"subject" : subject
                           };

    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary: dict];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    self.sentResponse = TRUE;

    // CFIndex count = 1;
    //
    // for (CFIndex i = 0; i < count; i++)
    // {
    //     SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, i);
    //     NSString* fingerprint = [self getFingerprint:certRef];
    //
    //     if ([self isFingerprintTrusted: fingerprint]) {
    //         CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
    //         [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    //         self.sentResponse = TRUE;
    //         break;
    //     }
    // }
    //
    // if (! self.sentResponse) {
    //     CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_NOT_SECURE"];
    //     [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    // }

}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
    connection = nil;

    NSString *resultCode = @"CONNECTION_FAILED. Details:";
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:errStr];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    connection = nil;

    if (![self sentResponse]) {
        // NSLog(@"Connection was not checked because it was cached. Considering it secure to not break your app.");
        // CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        NSString *errStr = @"CONNECTION_FINISHED. Details: URL loaded successfully without obtain any certificate, it might be caused by cached connection or not https protocol.";
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:errStr];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

- (NSString*) getFingerprint: (NSData*) certData {
    unsigned char sha1Bytes[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(certData.bytes, (int)certData.length, sha1Bytes);
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 3];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; ++i) {
        [fingerprint appendFormat:@"%02x ", sha1Bytes[i]];
    }
    return [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

- (BOOL) isFingerprintTrusted: (NSString*)fingerprint {
  for (NSString *fp in self._allowedFingerprints) {
    if ([fingerprint caseInsensitiveCompare: fp] == NSOrderedSame) {
      return YES;
    }
  }
  return NO;
}

@end


@interface SSLCertificateChecker ()

@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation SSLCertificateChecker

- (void)check:(CDVInvokedUrlCommand*)command {
    NSString *serverURL = [command.arguments objectAtIndex:0];
    BOOL allowUntrusted = [command.arguments count] > 1 && [[command.arguments objectAtIndex:1] boolValue];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL]];

    CustomURLConnectionDelegate *delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin:self
                                                                                     callbackId:command.callbackId
                                                                                 allowUntrusted:allowUntrusted];

    if (![NSURLConnection connectionWithRequest:request delegate:delegate]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_FAILED"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

@end
