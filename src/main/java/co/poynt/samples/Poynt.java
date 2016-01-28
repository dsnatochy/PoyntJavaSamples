package co.poynt.samples;


import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.OutputStream;
import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


/*
 * DISCLAIMER OF WARRANTY
 * 
 * This source code is provided "as is" and without warranties as to performance or merchantability. 
 * This source code is provided without any express or implied warranties whatsoever. 
 * Because of the diversity of conditions and hardware under which this source code may be used, 
 * no warranty of fitness for a particular purpose is offered. 
 * The user is advised to test the source code thoroughly before relying on it. 
 * The user must assume the entire risk of using the source code.
 */
public class Poynt{
	// copy your application id starting with urn:aid here
	private static String applicationId = "<your app id>";
	// private key for the app id downloaded from poynt.net
	private static String privateKeyFile = "src/privateKey.pem";
	
	private static String apiEndpoint = "https://services.poynt.net";

	private static String getJWT() throws Exception{
		File f = new File(privateKeyFile);
		InputStreamReader isr = new InputStreamReader(new FileInputStream(f));
		
		PEMParser pemParser = new PEMParser(isr);
		Object object = pemParser.readObject();
		PEMKeyPair kp = (PEMKeyPair) object;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		RSAPrivateKey privateKey = (RSAPrivateKey) converter.getPrivateKey(kp.getPrivateKeyInfo());
		pemParser.close();
		
		
		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(privateKey);
		
		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject(applicationId);
		claimsSet.setAudience(Arrays.asList(apiEndpoint));
		claimsSet.setIssuer(applicationId);
		claimsSet.setExpirationTime(new Date(new Date().getTime() + 360 * 1000));
		claimsSet.setIssueTime(new Date(new Date().getTime()));
		claimsSet.setJWTID(UUID.randomUUID().toString());
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
		
		// Compute the RSA signature
		signedJWT.sign(signer);
		
		String s = signedJWT.serialize();
		return s;
	}

	public static String getAccessToken() throws Exception{

		URL url = new URL(apiEndpoint + "/token");
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		conn.setRequestProperty("api-version", "1.2");
		conn.setRequestProperty("Poynt-Request-Id", UUID.randomUUID().toString());

		String postData = "grantType=urn:ietf:params:oauth:grant-type:jwt-bearer";
		postData += "&assertion=" + getJWT();
		OutputStream os = conn.getOutputStream();
		os.write(postData.getBytes());
		os.flush();

		if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
			throw new RuntimeException("Failed : HTTP error code : "
				+ conn.getResponseCode());
		}

		BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
		String response  = br.readLine();
		conn.disconnect();

		ObjectMapper mapper = new ObjectMapper();
		Map<?,?> map  = mapper.readValue(response, Map.class);
		return (String)map.get("accessToken");
			
	}
}

