/*
 * Copyright 2026 Kingsrook, LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package com.kingsrook.qbits.authentik;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.EnumSet;
import com.kingsrook.qbits.authentik.sync.AuthentikSyncTables;
import com.kingsrook.qbits.authentik.webhook.AuthentikWebhookRouteProvider;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.quartz.QuartzSchedulerMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.actions.customizers.QCodeLoader;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;
import com.kingsrook.qqq.middleware.javalin.QJavalinMetaData;
import com.kingsrook.qqq.middleware.javalin.QJavalinRouteProviderInterface;
import io.javalin.Javalin;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Exercise the public producer and native route loader, not manual sync setup.
 *******************************************************************************/
class AuthentikSyncRegistrationTest
{
   /***************************************************************************
    ** Metadata-only host; requests in this test stop before database access.
    ***************************************************************************/
   private QInstance host()
   {
      var instance = new QInstance();
      instance.addBackend(new RDBMSBackendMetaData().withName("local").withVendor(RDBMSBackendMetaData.VENDOR_H2));
      instance.addScheduler(new QuartzSchedulerMetaData().withName("sync-host"));
      return (instance);
   }

   /***************************************************************************
    ** Unique prefix and per-directory secret; upstream writes stay disabled.
    ***************************************************************************/
   private AuthentikQBitConfig config(String prefix)
   {
      return (AuthentikTestSupport.unitConfig().withTableNamePrefix(prefix).withLocalBackendName("local")
         .withWebhookSecret("test-secret-" + prefix)
         .withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.MIRROR, AuthentikFeature.WEBHOOK)));
   }

   /***************************************************************************
    ** All six tables and scheduled jobs are registered through the public API;
    ** repeated health validation must not treat owned metadata as a collision.
    ***************************************************************************/
   @Test
   void producerRegistersOptInStorageAndSchedules() throws Exception
   {
      var instance = host();
      var config = config("registration");
      new AuthentikQBitProducer().withQBitConfig(config).produce(instance);
      for(var table : AuthentikSyncTables.all(config))
      {
         assertThat(instance.getTable(table.getName()).getBackendName()).isEqualTo("local");
      }
      assertThat(instance.getProcess("registrationSyncIncremental").getSchedule().getRepeatSeconds()).isEqualTo(300);
      assertThat(instance.getProcess("registrationSyncInbox")).isNotNull();
      var errors = new ArrayList<String>();
      config.validate(instance, errors);
      assertThat(errors).isEmpty();
      assertThat(QJavalinMetaData.of(instance).getAdditionalRouteProviderReferences()).hasSize(1);
      var plain = AuthentikTestSupport.produce(AuthentikTestSupport.unitConfig());
      assertThat(plain.getTable("authentik_user_mirror")).isNull();
      assertThat(plain.getProcess("authentikSyncIncremental")).isNull();
   }

   /***************************************************************************
    ** Missing dependencies and collisions fail before creating the API backend.
    ***************************************************************************/
   @Test
   void invalidHostFailsBeforeProducerMutation()
   {
      var empty = new QInstance();
      assertThatThrownBy(() -> new AuthentikQBitProducer().withQBitConfig(config("missing")).produce(empty))
         .hasMessageContaining("RDBMS").hasMessageContaining("scheduler");
      assertThat(empty.getBackend("missingApi")).isNull();
      var instance = host();
      instance.addTable(new QTableMetaData().withName("collision_user_mirror"));
      assertThatThrownBy(() -> new AuthentikQBitProducer().withQBitConfig(config("collision")).produce(instance))
         .hasMessageContaining("already registered");
      assertThat(instance.getBackend("collisionApi")).isNull();
      var webhookOnly = config("missingMirror").withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.WEBHOOK));
      assertThatThrownBy(() -> new AuthentikQBitProducer().withQBitConfig(webhookOnly).produce(instance))
         .hasMessageContaining("WEBHOOK needs MIRROR");
   }

   /***************************************************************************
    ** Two bound providers use distinct secrets and paths. Live disablement
    ** removes access without changing either the other route or its secret.
    ***************************************************************************/
   @Test
   void nativeLoadedRoutesKeepNamespacesAndSecretsSeparate() throws Exception
   {
      var instance = host();
      var alpha = config("routeAlpha");
      var beta = config("routeBeta");
      new AuthentikQBitProducer().withNamespace("alpha").withQBitConfig(alpha).produce(instance);
      new AuthentikQBitProducer().withNamespace("beta").withQBitConfig(beta).produce(instance);
      var providers = new ArrayList<QJavalinRouteProviderInterface>();
      for(var reference : QJavalinMetaData.of(instance).getAdditionalRouteProviderReferences())
      {
         var provider = QCodeLoader.getAdHoc(QJavalinRouteProviderInterface.class, reference);
         provider.setQInstance(instance);
         providers.add(provider);
      }
      var server = Javalin.create(javalin -> providers.forEach(provider -> provider.acceptJavalinConfig(javalin)));
      try(var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build())
      {
         server.start("127.0.0.1", 0);
         var versions = java.util.List.<com.kingsrook.qqq.middleware.javalin.specs.AbstractMiddlewareVersion>of(
            new com.kingsrook.qqq.middleware.javalin.specs.v1.MiddlewareVersionV1());
         assertThat(com.kingsrook.qqq.middleware.javalin.specs.UiApiRouteAuditor.findUnspecifiedRoutes(server, versions)).isEmpty();
         com.kingsrook.qqq.middleware.javalin.specs.UiApiRouteAuditor.audit(server, versions, true);
         assertThat(AuthentikWebhookRouteProvider.path(alpha)).isEqualTo("/qqq/hooks/routeAlpha/webhook");
         assertThat(post(client, server.port(), alpha, "test-secret-routeBeta")).isEqualTo(401);
         assertThat(post(client, server.port(), beta, "test-secret-routeAlpha")).isEqualTo(401);
         assertThat(post(client, server.port(), alpha, "test-secret-routeAlpha")).isEqualTo(400);
         assertThat(post(client, server.port(), beta, "test-secret-routeBeta")).isEqualTo(400);
         alpha.withFeatures(EnumSet.of(AuthentikFeature.READ, AuthentikFeature.MIRROR));
         assertThat(post(client, server.port(), alpha, "test-secret-routeAlpha")).isEqualTo(404);
         assertThat(post(client, server.port(), beta, "test-secret-routeBeta")).isEqualTo(400);
      }
      finally
      {
         server.stop();
      }
   }

   /***************************************************************************
    ** Malformed body distinguishes authenticated routing from database writes.
    ***************************************************************************/
   private int post(HttpClient client, int port, AuthentikQBitConfig config, String secret) throws Exception
   {
      var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + AuthentikWebhookRouteProvider.path(config)))
         .header(AuthentikWebhookRouteProvider.SECRET_HEADER, secret).POST(HttpRequest.BodyPublishers.ofString("{}"))
         .timeout(java.time.Duration.ofSeconds(5)).build();
      return (client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode());
   }
}
