/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik.webhook;

import java.time.Duration;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.sync.AuthentikWebhookEnvelope;
import com.kingsrook.qbits.authentik.sync.AuthentikWebhookInbox;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.middleware.javalin.QJavalinRouteProviderInterface;
import io.javalin.config.JavalinConfig;
import io.javalin.http.Context;

/*******************************************************************************
 ** Authenticated durable ingress followed by inline or ESB notification.
 ** Optional middleware types stay isolated here. WEBHOOK enables registration.
 ******************************************************************************/
public class AuthentikWebhookRouteProvider implements QJavalinRouteProviderInterface,
   com.kingsrook.qqq.backend.core.model.metadata.code.InitializableViaCodeReference
{
   public static final String PATH = "/qqq/hooks/authentik/webhook";
   public static final String SECRET_HEADER = "X-QQQ-Webhook-Secret";
   private QInstance instance;
   private String backendName;
   private String path;

   /***************************************************************************
    ** Compatibility constructor for the default Authentik QBit.
    ***************************************************************************/
   public AuthentikWebhookRouteProvider()
   {
      backendName = "authentikApi";
      path = PATH;
   }

   /***************************************************************************
    ** Native code loading supplies routing names only, never a secret. Plain
    ** class references retain the default route for existing host integrations.
    ***************************************************************************/
   @Override
   public void initialize(com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference reference)
   {
      if(reference instanceof com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReferenceWithProperties properties)
      {
         Object backend = properties.getProperties().get("backendName");
         Object route = properties.getProperties().get("path");
         if(!(backend instanceof String name) || !name.matches("[A-Za-z][A-Za-z0-9]*")
            || !(route instanceof String value) || !value.matches("/qqq/hooks/([A-Za-z][A-Za-z0-9]*/)?webhook"))
         {
            throw (new IllegalArgumentException("Invalid Authentik webhook routing metadata."));
         }
         backendName = name;
         path = value;
      }
   }

   /***************************************************************************
    ** The validated component prefix is safe as a literal path segment. An
    ** unprefixed QBit gets its own path, distinct from the default prefix.
    ***************************************************************************/
   public static String path(com.kingsrook.qbits.authentik.AuthentikQBitConfig config)
   {
      String prefix = config.getTableNamePrefix();
      return (prefix == null || prefix.isBlank() ? "/qqq/hooks/webhook" : "/qqq/hooks/" + prefix + "/webhook");
   }

   /***************************************************************************
    ** Reject duplicate QBit routes without replacing the host's route metadata.
    ***************************************************************************/
   public static void validateRegistration(QInstance instance, com.kingsrook.qbits.authentik.AuthentikQBitConfig config, java.util.List<String> errors)
   {
      var metadata = com.kingsrook.qqq.middleware.javalin.QJavalinMetaData.of(instance);
      if(metadata != null && metadata.getAdditionalRouteProviderReferences() != null)
      {
         for(var reference : metadata.getAdditionalRouteProviderReferences())
         {
            if(AuthentikWebhookRouteProvider.class.getName().equals(reference.getName())
               && (reference instanceof com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReferenceWithProperties properties
                  ? path(config).equals(properties.getProperties().get("path")) : PATH.equals(path(config))))
            {
               errors.add("Authentik webhook route already registered: " + path(config));
            }
         }
      }
   }

   /***************************************************************************
    ** QQQ loads this bound provider through its standard additional-route API.
    ***************************************************************************/
   public static void register(QInstance instance, com.kingsrook.qbits.authentik.AuthentikQBitConfig config)
   {
      com.kingsrook.qqq.middleware.javalin.QJavalinMetaData.ofOrWithNew(instance).withAdditionalRouteProviderReference(
         new com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReferenceWithProperties(AuthentikWebhookRouteProvider.class,
            java.util.Map.of("backendName", config.getApiBackendName(), "path", path(config))));
   }

   /***************************************************************************
    ** Host instance is supplied by QJavalin before route registration.
    ***************************************************************************/
   @Override
   public void setQInstance(QInstance instance)
   {
      this.instance = instance;
   }

   /***************************************************************************
    ** This callback authenticates its shared secret rather than a UI session.
    ***************************************************************************/
   @Override
   public void acceptJavalinConfig(JavalinConfig config)
   {
      if(instance != null && instance.getBackend(getApiBackendName()) != null
         && AuthentikRuntime.forBackend(getApiBackendName()).getConfig().hasFeature(com.kingsrook.qbits.authentik.AuthentikFeature.WEBHOOK))
      {
         config.routes.post(path, this::receive);
      }
   }

   /***************************************************************************
    ** Hosts with a namespace can select their configured API backend.
    ***************************************************************************/
   protected String getApiBackendName()
   {
      return (backendName);
   }

   /***************************************************************************
    ** Authenticate before reading, bound actual bytes including chunked bodies,
    ** and acknowledge only committed receipt. Never log the header or payload.
    ***************************************************************************/
   private void receive(Context context)
   {
      var previous = QContext.capture();
      try
      {
         if(instance == null || instance.getBackend(getApiBackendName()) == null)
         {
            context.status(503);
            return;
         }
         var config = AuthentikRuntime.forBackend(getApiBackendName()).getConfig();
         if(!config.hasFeature(com.kingsrook.qbits.authentik.AuthentikFeature.WEBHOOK))
         {
            context.status(404);
            return;
         }
         String secret = config.getResolvedWebhookSecret();
         String supplied = context.header(SECRET_HEADER);
         AuthentikWebhookEnvelope.authenticate(secret, supplied);
         if(context.req().getContentLengthLong() > AuthentikWebhookEnvelope.MAX_BODY_BYTES)
         {
            context.status(413);
            return;
         }
         byte[] body = context.req().getInputStream().readNBytes(AuthentikWebhookEnvelope.MAX_BODY_BYTES + 1);
         if(body.length > AuthentikWebhookEnvelope.MAX_BODY_BYTES)
         {
            context.status(413);
            return;
         }
         var event = AuthentikWebhookEnvelope.receive(secret, supplied, body);
         QContext.init(instance, new QSystemUserSession(instance));
         new AuthentikWebhookInbox(config, Duration.ofMinutes(15)).accept(event);
         try
         {
            dispatch(config);
         }
         catch(Exception notificationFailure)
         {
            // Receipt is committed. The scheduled inbox poll recovers this;
            // never echo/log an exception containing broker or API details.
         }
         context.status(204);
      }
      catch(SecurityException denied)
      {
         context.status(401);
      }
      catch(IllegalArgumentException | org.json.JSONException malformed)
      {
         context.status(400);
      }
      catch(Exception unavailable)
      {
         context.status(503);
      }
      finally
      {
         QContext.init(previous);
      }
   }

   /***************************************************************************
    ** After-commit delivery seam; production uses the host's selected mode.
    ***************************************************************************/
   protected void dispatch(com.kingsrook.qbits.authentik.AuthentikQBitConfig config) throws Exception
   {
      com.kingsrook.qbits.authentik.sync.AuthentikEventDelivery.dispatch(config);
   }
}
