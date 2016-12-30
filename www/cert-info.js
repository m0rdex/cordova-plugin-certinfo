"use strict";
var exec = require('cordova/exec');

module.exports = {
  fetch: function(url, allowUntrusted) {
    if (!url || typeof url !== 'string' || url.slice(0, 6).toLowerCase() !== 'https:') {
      return Promise.reject(new Error('a valid url with https protocol must be given'));
    }
    return new Promise(function(resolve, reject) {
      exec(resolve, reject, 'CertInfo', 'fetch', [url, !!allowUntrusted]);
    });
  }
};
