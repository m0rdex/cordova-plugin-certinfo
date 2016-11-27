# Cordova SSL Certificate Info plugin (iOS, Android)

## 1. Description

This plugin is used for fetching SSL certificate information from given HTTPS URL 
including base64 encode certificate data, SHA-1 fingerprint and subject summary.

Use this plugin together with the modified version of 
[cordova-plugin-http](https://github.com/yyfearth/cordova-plugin-http)
plugin with SSL Pinning will add an extra layer of security by preventing 'Man in the Middle' attacks.

## 2. Installation

Latest stable version from npm:
```
$ cordova plugin add cordova-plugin-certinfo
```

Bleeding edge version from Github:
```
$ cordova plugin add https://github.com/yyfearth/cordova-plugin-certinfo
```

## 3. Usage

You can use the fetch method to load the certificate information.
- `certificate`: base64 encoded certificate data
- `subject`: subject principals returned from Android, subject summery/CN from iOS
- `fingerprint`: the SHA-1 fingerprint of the certificate

You can verify the fingerprint by opening the server URL in Chrome.
Then click the green certificate in front of the URL, click 'Connection',
'Certificate details', expand the details and scroll down to the SHA1 fingerprint.

```javascript
  var server = "https://build.phonegap.com";

  window.plugins.certInfo.fetch(serverUrl).then(function(info) {
    console.log(info.certificate, info.subject, info.fingerprint);
  }, function(err) {
    console.error(err); // may include CONNECTION_FAILED CONNECTION_FINISHED
  });
```

* On iOS, this plugin only return the subject summery, typically the CN value, of the certificate for the `subject`.
* On Android, the `subject` will return the subject principals, and `issuer` will return the issuer principals,
and `details` will return a very detailed description of the certificate.


## 4. Credits

This plugin is forked from the original repo [SSLCertificateChecker-PhoneGap-Plugin](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin) by EddyVerbruggen.

The iOS code was inspired by a closed-source, purely native certificate pinning implementation by Rob Bosman.

[Jacob Weber](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin/issues/9) did some great work to support checking multiple certificates on iOS, thanks!
