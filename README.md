# Cordova SSL/TLS Certificate Info plugin (iOS, Android)

## 1. Description

This plugin can be used to add an extra layer of security by preventing 'Man in the Middle' attacks.
When correctly used, it will be very hard for hackers to intercept communication between your app and your server,
because you can actively verify the SSL certificate of the server by comparing actual and expected fingerprints.

You may want to check the connection when the app is started, but you can choose to invoke this plugin
everytime you communicate with the server. In either case, you can add your logic to the success and error callbacks.

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

First obtain the fingerprint of the SSL certificate of your server(s).
You can find it f.i. by opening the server URL in Chrome. Then click the green certificate in front of the URL, click 'Connection',
'Certificate details', expand the details and scroll down to the SHA1 fingerprint.

```javascript
  var server = "https://build.phonegap.com";
  var fingerprint = "2B 24 1B E0 D0 8C A6 41 68 C2 BB E3 60 0A DF 55 1A FC A8 45";

  window.plugins.sslCertificateChecker.check(
          successCallback,
          errorCallback,
          server,
          fingerprint);

   function successCallback(message) {
     alert(message);
     // Message is always: CONNECTION_SECURE.
     // Now do something with the trusted server.
   }

   function errorCallback(message) {
     alert(message);
     if (message == "CONNECTION_NOT_SECURE") {
       // There is likely a man in the middle attack going on, be careful!
     } else if (message.indexOf("CONNECTION_FAILED") >- 1) {
       // There was no connection (yet). Internet may be down. Try again (a few times) after a little timeout.
     }
   }
```

Need more than one fingerprint? In case your certificate is about to expire, you can add it already to your app, while still supporting the old certificate.
Note you may want to force clients to update the app when the new certificate is activated.
```javascript
  // an array of any number of fingerprints
  var fingerprints = ["2B 24 1B E0 D0 8C A6 41 68 C2 BB E3 60 0A DF 55 1A FC A8 45", "SE CO ND", ..];

  window.plugins.sslCertificateChecker.check(
          successCallback,
          errorCallback,
          server,
          fingerprints);
```


## 4. Credits

This plugin is forked from the original repo [SSLCertificateChecker-PhoneGap-Plugin](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin) by EddyVerbruggen.

The iOS code was inspired by a closed-source, purely native certificate pinning implementation by Rob Bosman.

[Jacob Weber](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin/issues/9) did some great work to support checking multiple certificates on iOS, thanks!
