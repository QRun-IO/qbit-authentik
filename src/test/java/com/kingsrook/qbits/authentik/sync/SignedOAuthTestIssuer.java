/*
 * Copyright 2026 Kingsrook, LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kingsrook.qbits.authentik.sync;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;

/*******************************************************************************
 ** Loopback OIDC discovery and real RSA signatures for native verifier tests.
 ** This tests the wire protocol, not Authentik's issuance configuration.
 ******************************************************************************/
final class SignedOAuthTestIssuer implements AutoCloseable
{
   private final HttpServer server;
   private final RSAKey key;
   private final String issuer;
   private String callbackToken;
   private String refreshedToken;
   private final java.util.concurrent.atomic.AtomicInteger refreshRequests = new java.util.concurrent.atomic.AtomicInteger();
   private final java.util.concurrent.atomic.AtomicBoolean codeConsumed = new java.util.concurrent.atomic.AtomicBoolean();

   /***************************************************************************
    ** Unique ephemeral port and key; publish only the public JWK.
    ***************************************************************************/
   SignedOAuthTestIssuer() throws Exception
   {
      key = new RSAKeyGenerator(2048).keyID("test-key").generate();
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
      response("/.well-known/openid-configuration", new JSONObject().put("issuer", issuer).put("jwks_uri", issuer + "jwks")
         .put("authorization_endpoint", issuer + "authorize").put("token_endpoint", issuer + "token")
         .put("response_types_supported", java.util.List.of("code")).put("subject_types_supported", java.util.List.of("public"))
         .put("id_token_signing_alg_values_supported", java.util.List.of("RS256")).toString());
      response("/jwks", new JWKSet(key.toPublicJWK()).toString());
      server.createContext("/token", exchange ->
      {
         String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
         boolean refresh = "POST".equals(exchange.getRequestMethod()) && refreshedToken != null
            && body.contains("grant_type=refresh_token") && body.contains("refresh_token=fixture-refresh");
         boolean accepted = refresh || "POST".equals(exchange.getRequestMethod()) && callbackToken != null
            && body.contains("grant_type=authorization_code") && body.contains("code=fixture-code")
            && body.contains("code_verifier=" + "a".repeat(43)) && codeConsumed.compareAndSet(false, true);
         if(refresh)
         {
            refreshRequests.incrementAndGet();
         }
         JSONObject response = accepted ? new JSONObject().put("access_token", refresh ? refreshedToken : callbackToken).put("token_type", "Bearer").put("expires_in", 300)
            : new JSONObject().put("error", "invalid_grant");
         if(accepted && refreshedToken != null)
         {
            response.put("refresh_token", "fixture-refresh");
         }
         String json = response.toString();
         byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
         exchange.getResponseHeaders().set("Content-Type", "application/json");
         exchange.sendResponseHeaders(accepted ? 200 : 400, bytes.length);
         try(var output = exchange.getResponseBody())
         {
            output.write(bytes);
         }
         finally
         {
            exchange.close();
         }
      });
      server.start();
   }

   /***************************************************************************
    ** Issue one fixture code response through core's actual token HTTP exchange.
    ***************************************************************************/
   void allowCallback(String identityUuid) throws Exception
   {
      callbackToken = token(identityUuid);
   }

   /***************************************************************************
    ** Enable a real HTTP refresh exchange with a distinct signed access token.
    ***************************************************************************/
   void allowRefresh(String identityUuid) throws Exception
   {
      refreshedToken = token(identityUuid);
   }

   /***************************************************************************
    ** Prove resumption actually contacted the refresh endpoint.
    ***************************************************************************/
   int refreshRequests()
   {
      return (refreshRequests.get());
   }

   /***************************************************************************
    ** Exact trusted issuer configured on the host metadata.
    ***************************************************************************/
   String issuer()
   {
      return (issuer);
   }

   /***************************************************************************
    ** A signed access token with intentionally stale group claims.
    ***************************************************************************/
   String token(String identityUuid) throws Exception
   {
      Instant now = Instant.now();
      return (token(identityUuid, now, now.plusSeconds(300)));
   }

   /***************************************************************************
    ** Signed lifetime variants exercise age policy independently of JWT expiry.
    ***************************************************************************/
   String token(String identityUuid, Instant issued, Instant expires) throws Exception
   {
      var claims = new JWTClaimsSet.Builder().issuer(issuer).audience("refresh-test").subject("stable-subject").jwtID(java.util.UUID.randomUUID().toString())
         .issueTime(Date.from(issued)).expirationTime(Date.from(expires)).claim("scope", "openid profile")
         .claim("preferred_username", "sam").claim("groups", java.util.List.of("OldAdmin"))
         .claim("qqq_identity", Map.of("pk", 1, "uuid", identityUuid)).build();
      SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).type(new JOSEObjectType("at+jwt")).build(), claims);
      token.sign(new RSASSASigner(key));
      return (token.serialize());
   }

   /***************************************************************************
    ** Fixed public JSON responses, no token handling or logging.
    ***************************************************************************/
   private void response(String path, String json)
   {
      server.createContext(path, exchange ->
      {
         byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
         exchange.getResponseHeaders().set("Content-Type", "application/json");
         exchange.sendResponseHeaders(200, bytes.length);
         try(var output = exchange.getResponseBody())
         {
            output.write(bytes);
         }
         finally
         {
            exchange.close();
         }
      });
   }

   /***************************************************************************
    ** Stop only this fixture's listener.
    ***************************************************************************/
   @Override
   public void close()
   {
      server.stop(0);
   }
}
