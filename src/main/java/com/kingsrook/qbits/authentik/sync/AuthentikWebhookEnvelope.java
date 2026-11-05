/*
 * Copyright 2026 Kingsrook, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kingsrook.qbits.authentik.sync;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Set;
import java.util.UUID;
import org.json.JSONObject;
import com.kingsrook.qbits.authentik.client.AuthentikRedactor;

/*******************************************************************************
 ** Authenticated, bounded webhook hints. Never persist the original event body:
 ** Authentik model context can contain arbitrary attributes and sensitive data.
 ** A hint identifies what to re-read; it is never authority for a permission.
 *******************************************************************************/
public record AuthentikWebhookEnvelope(String eventPk, String action, Instant created,
   String username, String modelApp, String modelName, String modelPk, String app)
{
   public static final int MAX_BODY_BYTES = 65536;
   private static final Set<String> ACTIONS = Set.of("model_created", "model_updated", "model_deleted",
      "login", "login_failed", "password_set", "invitation_used", "user_write");

   /*******************************************************************************
    ** Authenticate before parsing. Hashes have fixed equal length for the
    ** constant-time comparison. Fail closed on missing configured credentials.
    ** Callers must also enforce the body limit while reading the HTTP request.
    *******************************************************************************/
   public static AuthentikWebhookEnvelope receive(String configuredSecret, String suppliedSecret, byte[] body)
   {
      authenticate(configuredSecret, suppliedSecret);
      return (parse(body));
   }

   /*******************************************************************************
    ** HTTP adapters authenticate before reading an untrusted request stream.
    *******************************************************************************/
   public static void authenticate(String configuredSecret, String suppliedSecret)
   {
      if(configuredSecret == null || configuredSecret.isBlank())
      {
         throw (new IllegalStateException("Webhook secret is not configured"));
      }
      if(suppliedSecret == null || suppliedSecret.length() > 4096 || !MessageDigest.isEqual(digest(configuredSecret), digest(suppliedSecret)))
      {
         throw (new SecurityException("Webhook authentication failed"));
      }
   }

   /*******************************************************************************
    ** Revalidate a previously authenticated inbox row. Never use this method
    ** on an HTTP request; receive performs the required authentication first.
    *******************************************************************************/
   public static AuthentikWebhookEnvelope fromStorage(String json)
   {
      return (parse(json == null ? null : json.getBytes(StandardCharsets.UTF_8)));
   }

   /*******************************************************************************
    ** Validate the bounded, allowlisted envelope shared by ingress and replay.
    *******************************************************************************/
   private static AuthentikWebhookEnvelope parse(byte[] body)
   {
      if(body == null || body.length == 0 || body.length > MAX_BODY_BYTES)
      {
         throw (new IllegalArgumentException("Invalid webhook body size"));
      }
      try
      {
         JSONObject object = new JSONObject(new String(body, StandardCharsets.UTF_8));
         String eventPk = string(object, "eventPk", 64, true);
         if(!UUID.fromString(eventPk).toString().equalsIgnoreCase(eventPk))
         {
            throw (new IllegalArgumentException());
         }
         eventPk = UUID.fromString(eventPk).toString();
         String action = string(object, "action", 40, true);
         if(!ACTIONS.contains(action))
         {
            throw (new IllegalArgumentException());
         }
         Instant created = OffsetDateTime.parse(string(object, "created", 64, true)).toInstant();
         JSONObject model = object.optJSONObject("model");
         // Login/invitation events may name another model. They still trigger
         // a re-read, but unrelated model context is never retained.
         if(!action.startsWith("model_") && model != null
            && (!"authentik_core".equals(model.optString("app")) || !Set.of("user", "group").contains(model.optString("model_name"))))
         {
            model = null;
         }
         String modelApp = null;
         String modelName = null;
         String modelPk = null;
         if(model != null)
         {
            modelApp = string(model, "app", 64, true);
            modelName = string(model, "model_name", 64, true);
            Object pk = model.opt("pk");
            modelPk = pk instanceof Number ? pk.toString() : string(model, "pk", 64, true);
            if(!"authentik_core".equals(modelApp) || !Set.of("user", "group").contains(modelName)
               || modelPk.length() > 64 || !modelPk.matches("[A-Za-z0-9_-]+"))
            {
               throw (new IllegalArgumentException());
            }
         }
         if(action.startsWith("model_") && model == null)
         {
            throw (new IllegalArgumentException());
         }
         return (new AuthentikWebhookEnvelope(eventPk, action, created, string(object, "username", 255, false),
            modelApp, modelName, modelPk, string(object, "app", 255, false)));
      }
      catch(RuntimeException e)
      {
         // JSON/date exceptions can echo payload values. Do not retain causes.
         throw (new IllegalArgumentException("Invalid webhook envelope"));
      }
   }

   /*******************************************************************************
    ** Persist only the allowlisted transport mapping fields.
    *******************************************************************************/
   public String storageJson()
   {
      JSONObject object = new JSONObject().put("eventPk", eventPk).put("action", action)
         .put("created", created.toString()).put("username", username).put("app", app);
      if(modelPk != null)
      {
         object.put("model", new JSONObject().put("app", modelApp).put("model_name", modelName).put("pk", modelPk));
      }
      return (AuthentikRedactor.redactText(object.toString(), null));
   }

   /*******************************************************************************
    ** Strict strings only; JSON objects are never coerced into stored text.
    *******************************************************************************/
   private static String string(JSONObject object, String key, int max, boolean required)
   {
      Object raw = object.opt(key);
      if(raw == null || JSONObject.NULL.equals(raw))
      {
         if(required)
         {
            throw (new IllegalArgumentException());
         }
         return (null);
      }
      if(!(raw instanceof String value) || value.length() > max || (required && value.isBlank()))
      {
         throw (new IllegalArgumentException());
      }
      return (value);
   }

   /*******************************************************************************
    ** SHA-256 is required by every Java platform; no secret is logged or held
    ** in the returned envelope.
    *******************************************************************************/
   private static byte[] digest(String value)
   {
      try
      {
         return (MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
      }
      catch(NoSuchAlgorithmException e)
      {
         throw (new IllegalStateException("SHA-256 is unavailable"));
      }
   }
}
