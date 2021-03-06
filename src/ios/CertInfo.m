#import "CertInfo.h"
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
    SecTrustResultType trustResultType;
    SecTrustEvaluate(trustRef, &trustResultType);
    NSString* errMsg = @"CONNECTION_NOT_SECURE";

    [connection cancel];

    BOOL trusted = kSecTrustResultProceed == trustResultType || kSecTrustResultUnspecified == trustResultType;
    if (!trusted) {
        NSArray* props = CFBridgingRelease(SecTrustCopyProperties(trustRef));
        if (props != NULL) {
            errMsg = [[props objectAtIndex:0] valueForKey:@"value"];
        }
    }

    SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, 0);
    NSData* certData = (NSData*) CFBridgingRelease(SecCertificateCopyData(certRef));

    if (certData == NULL || (!trusted && !self._allowUntrusted)) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:errMsg];
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


    if (!trusted) {
        dict = [dict mutableCopy];
        [dict setValue:errMsg forKey:@"error"];

        NSDictionary* err = CFBridgingRelease(SecTrustCopyResult(trustRef));
        NSArray* details = [[err objectForKey:@"TrustResultDetails"] valueForKey:@"SSLHostname"];
        BOOL mismatched = [details  containsObject: @NO];
        [dict setValue:@(mismatched) forKey:@"mismatched"];
    }

    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary: dict];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    self.sentResponse = TRUE;
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

@end


@interface CertInfo ()

@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation CertInfo

- (void)fetch:(CDVInvokedUrlCommand*)command {
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
