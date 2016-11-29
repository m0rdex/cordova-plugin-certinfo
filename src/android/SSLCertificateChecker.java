package nl.xservices.plugins;

import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import javax.security.cert.CertificateException;
import java.io.IOException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class SSLCertificateChecker extends CordovaPlugin {

  private static final String ACTION_CHECK_EVENT = "check";
  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    if (ACTION_CHECK_EVENT.equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          try {
            final String serverURL = args.getString(0);
            //final JSONArray allowedFingerprints = args.getJSONArray(2);
            final X509Certificate cert = getCertificate(serverURL);
            final byte[] data = cert.getEncoded();
            final String fingerprint = getFingerprint(data);
            final JSONObject json = new JSONObject();
            json.put("certificate", Base64.encodeToString(data, Base64.NO_WRAP));
            json.put("fingerprint", fingerprint);
            json.put("subject", cert.getSubjectX500Principal());
            json.put("issuer", cert.getIssuerX500Principal());
            json.put("details", cert.toString());
            callbackContext.success(json);
            //for (int j=0; j<allowedFingerprints.length(); j++) {
            //  if (allowedFingerprints.get(j).toString().equalsIgnoreCase(serverCertFingerprint)) {
            //    callbackContext.success("CONNECTION_SECURE");
            //    return;
            //  }
            //}
            //callbackContext.error("CONNECTION_NOT_SECURE");
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

  private static X509Certificate getCertificate(String httpsURL) throws IOException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
    final HttpsURLConnection con = (HttpsURLConnection) new URL(httpsURL).openConnection();
    con.setConnectTimeout(5000);
    con.connect();
    return (X509Certificate)con.getServerCertificates()[0];
  }

  private static String getFingerprint(final byte[] data) throws IOException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {
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
