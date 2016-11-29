"use strict";
var exec = require('cordova/exec');

module.exports = {
  fetch: function(serverURL) {
    return new Promise(function(resolve, reject) {
      exec(resolve, reject, "CertInfo", "fetch", [serverURL]);
    });
  }
};
