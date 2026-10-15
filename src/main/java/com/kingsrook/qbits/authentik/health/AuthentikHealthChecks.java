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

package com.kingsrook.qbits.authentik.health;


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.client.AuthentikJson;
import com.kingsrook.qbits.authentik.client.AuthentikTokenBroker;
import com.kingsrook.qbits.authentik.drift.AuthentikDriftReport;
import com.kingsrook.qbits.authentik.drift.DriftFinding;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.health.HealthCategory;
import com.kingsrook.qqq.backend.core.health.HealthCheckKind;
import com.kingsrook.qqq.backend.core.health.HealthCheckMetaData;
import com.kingsrook.qqq.backend.core.health.HealthCheckOutcome;
import com.kingsrook.qqq.backend.core.health.HealthChecksMetaData;
import com.kingsrook.qqq.backend.core.health.HealthDetails;
import com.kingsrook.qqq.backend.core.health.HealthStatus;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import org.json.JSONObject;


/*******************************************************************************
 ** Central identity checks reuse the qbit client and configuration diagnostics.
 *******************************************************************************/
public final class AuthentikHealthChecks
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuthentikHealthChecks()
   {
   }



   /*******************************************************************************
    ** Called only after the producer has validated and registered the runtime.
    *******************************************************************************/
   public static void register(QInstance instance, AuthentikQBitConfig config)
   {
      HealthChecksMetaData registry = HealthChecksMetaData.ofOrWithNew(instance);
      for(String name : List.of("api", "api_token", "mapper", "token_broker"))
      {
         registry.withCheck(new HealthCheckMetaData().withName("authentik." + name).withLabel("Authentik " + name)
            .withComponent("authentik").withCategory(HealthCategory.IDENTITY).withKind(HealthCheckKind.DEPENDENCY)
            .withIntervalSeconds(name.equals("api") || name.equals("token_broker") ? 300 : 21600)
            .withTimeoutMs(10000).withCheckInstance(input ->
            {
               try
               {
                  AuthentikActionUtil util = AuthentikActionUtil.forBackend(config.getApiBackendName()).withHealthDeadline(input.getDeadline());
                  HealthCheckOutcome outcome;
                  switch(name)
                  {
                     case "api" -> outcome = api(util, config);
                     case "api_token" -> outcome = apiToken(util, Instant.now());
                     case "mapper" -> outcome = mapper(util, config);
                     default -> outcome = tokenBroker(util, config);
                  }
                  return (Instant.now().isBefore(input.getDeadline()) && !Thread.currentThread().isInterrupted()
                     ? outcome : HealthCheckOutcome.down("Authentik health deadline exceeded"));
               }
               catch(Exception e)
               {
                  // Never copy exception messages, URLs or credential values into outcomes.
                  return (HealthCheckOutcome.down("Authentik health check failed"));
               }
            }));
      }
   }



   /*******************************************************************************
    ** Version compatibility follows the existing drift report's prefix rule.
    *******************************************************************************/
   private static HealthCheckOutcome api(AuthentikActionUtil util, AuthentikQBitConfig config)
   {
      String version = util.fetchServerVersion().orElse("");
      if(!version.matches("[0-9]{1,4}(\\.[0-9]{1,4}){1,3}"))
      {
         return (HealthCheckOutcome.down("Authentik server version unavailable"));
      }
      String expected = config.getExpectedServerVersion();
      boolean matches = !StringUtils.hasContent(expected) || version.equals(expected) || version.startsWith(expected + ".");
      return ((matches ? HealthCheckOutcome.up("Authentik API reachable") : HealthCheckOutcome.degraded("Authentik server version differs"))
         .withDetails(new HealthDetails().withValue("serverVersion", version)));
   }



   /*******************************************************************************
    ** The service account should have one API token; never read its key.
    *******************************************************************************/
   private static HealthCheckOutcome apiToken(AuthentikActionUtil util, Instant now) throws QException
   {
      List<JSONObject> tokens = util.getServiceAccountApiTokens();
      if(tokens.isEmpty())
      {
         return (HealthCheckOutcome.down("API token missing"));
      }
      if(tokens.size() != 1)
      {
         return (HealthCheckOutcome.unknown("API token cannot be identified uniquely"));
      }
      JSONObject token = tokens.getFirst();
      if(!token.optBoolean("expiring", true))
      {
         return (HealthCheckOutcome.up("API token present without expiry"));
      }
      Instant expires;
      try
      {
         expires = AuthentikJson.parseInstant(token.optString("expires", null));
      }
      catch(java.time.format.DateTimeParseException e)
      {
         return (HealthCheckOutcome.unknown("API token expiry unavailable"));
      }
      if(expires == null)
      {
         return (HealthCheckOutcome.unknown("API token expiry unavailable"));
      }
      HealthCheckOutcome outcome = !expires.isAfter(now) ? HealthCheckOutcome.down("API token expired")
         : expires.isBefore(now.plus(14, ChronoUnit.DAYS)) ? HealthCheckOutcome.degraded("API token expires within 14 days")
         : HealthCheckOutcome.up("API token present");
      return (outcome.withDetails(new HealthDetails().withValue("daysToExpiry", ChronoUnit.DAYS.between(now, expires))));
   }



   /*******************************************************************************
    ** Findings carry fixed codes only, never subjects or diagnostic messages.
    *******************************************************************************/
   private static HealthCheckOutcome mapper(AuthentikActionUtil util, AuthentikQBitConfig config)
   {
      HealthStatus status = HealthStatus.UP;
      TreeSet<String> codes = new TreeSet<>();
      for(DriftFinding finding : new AuthentikDriftReport(util, config).runMapperChecks())
      {
         if(finding.severity() == DriftFinding.Severity.ERROR || finding.severity() == DriftFinding.Severity.WARNING)
         {
            String code = "group attributes".equals(finding.check()) ? "group_attributes" : "service_account_activity";
            codes.add(code + "." + finding.severity().name().toLowerCase(java.util.Locale.ROOT));
            if(finding.severity() == DriftFinding.Severity.ERROR)
            {
               status = HealthStatus.DOWN;
            }
            else if(status != HealthStatus.DOWN)
            {
               status = HealthStatus.DEGRADED;
            }
         }
      }
      return (new HealthCheckOutcome().withStatus(status).withMessage(status == HealthStatus.UP ? "Mapper checks passed" : "Mapper drift detected")
         .withDetails(new HealthDetails().withValue("findingCodes", String.join(",", codes))));
   }



   /*******************************************************************************
    ** Authenticate through the existing broker transport, retaining no bearer.
    *******************************************************************************/
   private static HealthCheckOutcome tokenBroker(AuthentikActionUtil util, AuthentikQBitConfig config) throws QException
   {
      if(!StringUtils.hasContent(config.getTokenBrokerClientId()) || !StringUtils.hasContent(config.getTokenBrokerClientSecret()))
      {
         return (HealthCheckOutcome.unknown("not configured"));
      }
      new AuthentikTokenBroker().probeClientCredentials(util);
      return (HealthCheckOutcome.up("Token broker authenticated"));
   }
}
