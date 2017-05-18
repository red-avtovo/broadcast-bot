package executors

@Grab('org.codehaus.groovy.modules.http-builder:http-builder:0.7')
import groovy.json.JsonBuilder
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.Method
import org.apache.http.conn.scheme.Scheme
import org.apache.http.conn.ssl.SSLSocketFactory

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.SignatureException

import static groovyx.net.http.ContentType.JSON

static def hmac(String data, String key) throws SignatureException {
    String result
    try {
        // get an hmac_sha1 key from the raw key bytes
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");

        // get an hmac_sha1 Mac instance and initialize with the signing key
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);

        // compute the hmac on input data bytes
        byte[] rawHmac = mac.doFinal(data.getBytes());
        result = rawHmac.encodeHex()
    } catch (Exception e) {
        throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
    }
    return result
}

static def ignoreSslIssues(HTTPBuilder http) {
    def sslContext = SSLContext.getInstance("SSL")
    def nullTrustManager = [
            checkClientTrusted: { chain, authType -> },
            checkServerTrusted: { chain, authType -> },
            getAcceptedIssuers: { null }
    ]
    sslContext.init(null, [nullTrustManager as X509TrustManager] as TrustManager[], null)
    def sf = new SSLSocketFactory(sslContext, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
    def httpsScheme = new Scheme("https", sf, 443)
    http.client.connectionManager.schemeRegistry.register(httpsScheme)
}

//======================================================================================================================
def url = "<broadcast host>:<port>/broadcast/v1"
def message = ""
def key = ""


def hmac = hmac(message, key)
def json = new JsonBuilder([signature: hmac, message: message])
//print json.toString()
def http = new HTTPBuilder(url)
ignoreSslIssues(http)
http.request(Method.POST, JSON) { req ->
    body = json.toString()

    response.success = { resp, respjson ->
        // response handling here
    }
}
