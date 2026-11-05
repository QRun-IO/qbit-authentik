/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.security;

import java.net.URI;

/*******************************************************************************
 ** Source-instance boundary after native OAuth signature/issuer verification.
 ** The host declares the public URL of its API-backed Authentik installation.
 ** Core still owns the exact provider/audience allowlist; this adds no trust.
 *******************************************************************************/
public final class AuthentikIssuer
{
   /***************************************************************************
    ** Utility class.
    ***************************************************************************/
   private AuthentikIssuer()
   {
   }

   /***************************************************************************
    ** Accept the configured public origin and deployment path only. Both global
    ** and per-provider issuer paths are supported within that installation.
    ** Reject ambiguous URL spellings rather than interpreting them differently
    ** from the provider or proxy. Never fetch a URL supplied by a claim.
    ***************************************************************************/
   public static boolean matches(String publicUrl, Object verifiedIssuer)
   {
      if(publicUrl == null || !(verifiedIssuer instanceof String issuer) || issuer.isBlank()
         || issuer.length() > 2048 || publicUrl.length() > 2048)
      {
         return (false);
      }
      try
      {
         URI base = URI.create(publicUrl);
         URI source = URI.create(issuer);
         if(!canonical(base) || !canonical(source) || !base.getScheme().equalsIgnoreCase(source.getScheme())
            || !base.getHost().equalsIgnoreCase(source.getHost()) || port(base) != port(source))
         {
            return (false);
         }
         String root = base.getPath().replaceAll("/+$", "");
         String path = source.getPath().replaceAll("/+$", "");
         return (path.equals(root) || path.startsWith(root + "/"));
      }
      catch(IllegalArgumentException malformed)
      {
         return (false);
      }
   }

   /***************************************************************************
    ** Only unambiguous absolute HTTP(S) origins and unescaped paths are allowed.
    ***************************************************************************/
   private static boolean canonical(URI uri)
   {
      return (uri.getScheme() != null && (uri.getScheme().equalsIgnoreCase("https") || uri.getScheme().equalsIgnoreCase("http"))
         && uri.getHost() != null && uri.getPort() <= 65535 && uri.getPort() != 0 && uri.getRawUserInfo() == null
         && uri.getRawQuery() == null && uri.getRawFragment() == null && uri.getPath() != null
         && uri.getPath().equals(uri.getRawPath()) && !uri.getPath().contains("//")
         && uri.getPath().equals(uri.normalize().getPath()));
   }

   /***************************************************************************
    ** Explicit default ports and implicit default ports denote the same origin.
    ***************************************************************************/
   private static int port(URI uri)
   {
      return (uri.getPort() == -1 ? (uri.getScheme().equalsIgnoreCase("https") ? 443 : 80) : uri.getPort());
   }
}
