package com.kingsrook.qbits.authentik.security;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Public-origin/path comparison cannot accept lookalikes or URL ambiguity.
 *******************************************************************************/
class AuthentikIssuerTest
{
   /***************************************************************************
    ** Public API aliases, default ports and deployments under a path are valid.
    ***************************************************************************/
   @Test
   void matchesOnlyTheConfiguredInstallation()
   {
      assertThat(AuthentikIssuer.matches("https://sso.example.test", "https://sso.example.test/")).isTrue();
      assertThat(AuthentikIssuer.matches("https://SSO.example.test:443/", "https://sso.example.test/application/o/app/")).isTrue();
      assertThat(AuthentikIssuer.matches("http://127.0.0.1:1234/", "http://127.0.0.1:1234/application/o/app/")).isTrue();
      assertThat(AuthentikIssuer.matches("https://sso.example.test/auth/", "https://sso.example.test/auth/application/o/app/")).isTrue();
      assertThat(AuthentikIssuer.matches("https://sso.example.test/auth/", "https://sso.example.test/auth")).isTrue();
      assertThat(AuthentikIssuer.matches("https://sso.example.test/auth/", "https://sso.example.test/auth-other/")).isFalse();
      assertThat(AuthentikIssuer.matches("https://sso.example.test/auth/", "https://sso.example.test/other/")).isFalse();
   }

   /***************************************************************************
    ** No coercion, userinfo, alternate origin or encoded path interpretation.
    ***************************************************************************/
   @Test
   void rejectsAmbiguousAndForeignSources()
   {
      String root = "https://sso.example.test/auth/";
      for(String issuer : List.of("", "/auth/", "https://sso.example.test.evil.test/auth/", "http://sso.example.test/auth/",
         "https://sso.example.test:444/auth/", "https://user@sso.example.test/auth/", "https://sso.example.test/auth/?x=1",
         "https://sso.example.test/auth/#fragment", "https://sso.example.test/auth/../other/", "https://sso.example.test/auth/%2e%2e/other/",
         "https://sso.example.test/auth//application/", "https://sso.example.test:0/auth/", "https://sso.example.test:65536/auth/"))
      {
         assertThat(AuthentikIssuer.matches(root, issuer)).as(issuer).isFalse();
      }
      assertThat(AuthentikIssuer.matches(root, null)).isFalse();
      assertThat(AuthentikIssuer.matches(root, 42)).isFalse();
      assertThat(AuthentikIssuer.matches(null, root)).isFalse();
      assertThat(AuthentikIssuer.matches("https://user@sso.example.test/auth/", root)).isFalse();
   }
}
