package nl.xservices.plugins;

import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
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
import javax.net.ssl.X509TrustManager;

public class SSLCertificateChecker extends CordovaPlugin {

  private static final String ACTION_CHECK_EVENT = "check";
  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  private static SSLSocketFactory TRUSTED_FACTORY;
  private static HostnameVerifier TRUSTED_VERIFIER;

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    if (ACTION_CHECK_EVENT.equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          try {
            boolean trusted = true;
            X509Certificate cert;
            final String serverURL = args.getString(0);
            final boolean allowUntrusted = args.length() > 1 && args.getBoolean(1);
            try {
              cert = getCertificate(serverURL, false);
            } catch (Exception ex) {
              if (allowUntrusted) {
                trusted = false;
                cert = getCertificate(serverURL, true);
              } else {
                throw ex;
              }
            }
            final byte[] data = cert.getEncoded();
            final String fingerprint = getFingerprint(data);
            final JSONObject json = new JSONObject();
            json.put("trusted", trusted);
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
      callbackContext.error("sslCertificateChecker." + action + " is not a supported function. Did you mean '" + ACTION_CHECK_EVENT + "'?");
      return false;
    }
  }

  private static SSLSocketFactory getTrustedFactory() throws IOException {
    if (TRUSTED_FACTORY == null) {
      final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

        public X509Certificate[] getAcceptedIssuers() {
          return new X509Certificate[0];
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) {
          // Intentionally left blank
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) {
          // Intentionally left blank
        }
      }};
      try {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAllCerts, new SecureRandom());

        TRUSTED_FACTORY = context.getSocketFactory();
      } catch (GeneralSecurityException e) {
        throw new IOException("Security exception configuring SSL context", e);
      }
    }

    return TRUSTED_FACTORY;
  }

  private static HostnameVerifier getTrustedVerifier() {
    if (TRUSTED_VERIFIER == null)
      TRUSTED_VERIFIER = new HostnameVerifier() {

        public boolean verify(String hostname, SSLSession session) {
          return true;
        }
      };

    return TRUSTED_VERIFIER;
  }

  private static X509Certificate getCertificate(String httpsURL, boolean trustAllCert) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
    final HttpsURLConnection con = (HttpsURLConnection) new URL(httpsURL).openConnection();
    if (trustAllCert) {
      con.setSSLSocketFactory(getTrustedFactory());
      con.setHostnameVerifier(getTrustedVerifier());
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
