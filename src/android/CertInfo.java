package org.apache.cordova.certinfo;

import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CertInfo extends CordovaPlugin {

  private static final String ACTION_CHECK_EVENT = "check";
  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  private static class CertificateResult {
    private Exception exception = null;
    private boolean domainMismatched = false;

    public boolean isTrusted() {
      return exception == null;
    }

    public Exception getException() {
      return exception;
    }

    public void setException(Exception ex) {
      exception = ex;
    }

    public boolean isDomainMismatched() {
      return domainMismatched;
    }

    public void setDomainMismatched(boolean domainMismatched) {
      this.domainMismatched = domainMismatched;
    }
  }

  private static class TrustManagerDelegate implements X509TrustManager {
    private CertificateResult certificateResult = null;
    private static X509TrustManager DEFAULT_TRUST_MANAGER;

    static {
      try {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        TrustManager[] trustManagers = factory.getTrustManagers();
        for (TrustManager tm : trustManagers) {
          if (tm instanceof X509TrustManager) {
            DEFAULT_TRUST_MANAGER = (X509TrustManager) tm;
            break;
          }
        }
      } catch (NoSuchAlgorithmException | KeyStoreException e) {
        e.printStackTrace();
      }
    }

    public CertificateResult getCertificateResult() {
      return certificateResult;
    }

    public void setCertificateResult(CertificateResult certificateResult) {
      this.certificateResult = certificateResult;
    }

    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
      DEFAULT_TRUST_MANAGER.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
      try {
        DEFAULT_TRUST_MANAGER.checkServerTrusted(chain, authType);
      } catch (CertificateException ex) {
        if (certificateResult == null) {
          throw ex;
        } else {
          certificateResult.setException(ex);
        }
      }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return DEFAULT_TRUST_MANAGER.getAcceptedIssuers();
    }
  }

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    if (ACTION_CHECK_EVENT.equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          try {
            X509Certificate cert;
            final String serverURL = args.getString(0);
            final boolean allowUntrusted = args.length() > 1 && args.getBoolean(1);
            CertificateResult result = allowUntrusted ? new CertificateResult() : null;
            cert = getCertificate(serverURL, result);
            final byte[] data = cert.getEncoded();
            final String fingerprint = getFingerprint(data);
            final JSONObject json = new JSONObject();
            json.put("trusted", result == null || result.isTrusted());
            if (result != null && !result.isTrusted()) {
              json.put("mismatched", result.isDomainMismatched());
              json.put("error", result.getException().getMessage());
            }
            json.put("certificate", Base64.encodeToString(data, Base64.NO_WRAP));
            json.put("fingerprint", fingerprint);
            json.put("subject", cert.getSubjectX500Principal());
            json.put("issuer", cert.getIssuerX500Principal());
            callbackContext.success(json);
          } catch (Exception e) {
            callbackContext.error("CONNECTION_FAILED. Details: " + e.getMessage());
          }
        }
      });
      return true;
    } else {
      callbackContext.error("CertInfo." + action + " is not a supported function. Did you mean '" + ACTION_CHECK_EVENT + "'?");
      return false;
    }
  }

  private static SSLSocketFactory getTrustedFactory(final CertificateResult result) throws IOException {
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      TrustManagerDelegate tm = new TrustManagerDelegate();
      tm.setCertificateResult(result);
      context.init(null, new TrustManager[]{tm}, new SecureRandom());

      return context.getSocketFactory();
    } catch (GeneralSecurityException e) {
      throw new IOException("Security exception configuring SSL context", e);
    }
  }

  private static HostnameVerifier getTrustedVerifier(final CertificateResult result) {
    return new HostnameVerifier() {

      public boolean verify(String hostname, SSLSession session) {
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)) {
          result.setException(new CertificateException("Hostname not matched"));
          result.setDomainMismatched(true);
        }
        return true;
      }
    };
  }

  private static X509Certificate getCertificate(String httpsURL, final CertificateResult result) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
    final HttpsURLConnection con = (HttpsURLConnection) new URL(httpsURL).openConnection();
    if (result != null) {
      con.setSSLSocketFactory(getTrustedFactory(result));
      con.setHostnameVerifier(getTrustedVerifier(result));
    }
    con.setConnectTimeout(5000);
    con.connect();
    X509Certificate certificate = (X509Certificate) con.getServerCertificates()[0];
    con.disconnect();
    return certificate;
  }

  private static String getFingerprint(final byte[] data) throws IOException, NoSuchAlgorithmException, CertificateException {
    final MessageDigest md = MessageDigest.getInstance("SHA1");
    md.update(data);
    return dumpHex(md.digest());
  }

  private static String dumpHex(byte[] data) {
    final int n = data.length;
    final StringBuilder sb = new StringBuilder(n * 3 - 1);
    for (int i = 0; i < n; i++) {
      if (i > 0) {
        sb.append(' ');
      }
      sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
      sb.append(HEX_CHARS[data[i] & 0x0F]);
    }
    return sb.toString();
  }
}
