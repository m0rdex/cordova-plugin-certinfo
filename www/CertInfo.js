"use strict";
var exec = require('cordova/exec');

module.exports = {
  check: function (successCallback, errorCallback, serverURL, allowedSHA1FingerprintOrArray, allowedSHA1FingerprintAlt) {
    if (typeof errorCallback != "function") {
      console.log("CertInfo.find failure: errorCallback parameter must be a function");
      return
    }

    if (typeof successCallback != "function") {
      console.log("CertInfo.find failure: successCallback parameter must be a function");
      return
    }

    // if an array is not passed, transform the input into one
    var fpArr = [];
    if (allowedSHA1FingerprintOrArray !== undefined) {
      if (typeof allowedSHA1FingerprintOrArray == "string") {
        fpArr.push(allowedSHA1FingerprintOrArray);
      } else {
        fpArr = allowedSHA1FingerprintOrArray.slice(0);
      }
    }
    if (allowedSHA1FingerprintAlt !== undefined) {
      fpArr.push(allowedSHA1FingerprintAlt);
    }
    exec(successCallback, errorCallback, "CertInfo", "check", [serverURL, false, fpArr]);
  }
};
