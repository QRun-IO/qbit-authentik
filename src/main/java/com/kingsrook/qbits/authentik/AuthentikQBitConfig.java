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

package com.kingsrook.qbits.authentik;


import java.net.URI;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.kingsrook.qbits.authentik.policy.PolicyFormat;
import com.kingsrook.qqq.backend.core.instances.QMetaDataVariableInterpreter;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitConfig;
import com.kingsrook.qqq.backend.core.utils.StringUtils;


/*******************************************************************************
 ** Host-facing configuration of the Authentik QBit (DESIGN.md section 3.2).
 **
 ** Secrets (apiToken, webhookSecret) may be given as ${env.NAME} references;
 ** the qbit resolves them itself (APIBackendMetaData.enrich() is disabled in
 ** QQQ), never serializes them, and redacts them in toString().
 **
 ** validate() is list-based and never throws; the producer fails production
 ** with all collected errors.
 *******************************************************************************/
public class AuthentikQBitConfig implements QBitConfig
{
   /** Features implemented in this release. Others are refused by validate(). */
   public static final Set<AuthentikFeature> AVAILABLE_FEATURES = EnumSet.of(AuthentikFeature.READ, AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP,
      AuthentikFeature.CREDENTIALS, AuthentikFeature.SESSIONS, AuthentikFeature.POLICIES, AuthentikFeature.DELETE);

   /** Features that change Authentik data; they need a local backend for the audit trail. */
   public static final Set<AuthentikFeature> WRITE_FEATURES = EnumSet.of(AuthentikFeature.USERS, AuthentikFeature.GROUPS, AuthentikFeature.MEMBERSHIP,
      AuthentikFeature.CREDENTIALS, AuthentikFeature.SESSIONS, AuthentikFeature.POLICIES, AuthentikFeature.DELETE);

   private static final Pattern APP_KEY_PATTERN = Pattern.compile("[a-z0-9][a-z0-9-]{0,48}[a-z0-9]");
   private static final Pattern PREFIX_PATTERN  = Pattern.compile("[a-zA-Z][a-zA-Z0-9]{0,30}");

   private String                baseUrl;
   private String                apiToken;
   private String                appKey;
   private String                tableNamePrefix          = "authentik";
   private Set<AuthentikFeature> features                 = EnumSet.of(AuthentikFeature.READ);
   private Boolean               readOnly                 = false;
   private String                serviceAccountUsername;
   private String                userScopePathStartsWith;
   private List<String>          userScopeGroupNames      = new ArrayList<>();
   private String                groupScopeNamePrefix;
   private List<String>          protectedUsernames       = new ArrayList<>();
   private String                bootstrapOperatorSubjects       = "${env.AUTHENTIK_QBIT_BOOTSTRAP_SUBJECTS}";
   private List<String>          applicationsInScope      = new ArrayList<>();
   private String                localBackendName;
   private Boolean               twoPersonApproval        = true;
   private String                schedulerName;
   private String                linkPrefix               = "/app";
   private String                recoveryEmailStage;
   private String                invitationFlow;
   private String                newUserPath              = "users";
   private String                webhookSecret            = "${env.AUTHENTIK_WEBHOOK_SECRET}";
   private Integer               throttleRequestsPerSecond = 10;
   private Integer               throttleBurst            = 20;
   private Integer               bulkPacingMillis         = 100;
   private Integer               listCacheTtlSeconds      = 30;
   private Integer               groupCacheTtlSeconds     = 60;
   private Integer               connectTimeoutMillis     = 5_000;
   private Integer               socketTimeoutMillis      = 30_000;
   private String                expectedServerVersion    = "2026.8";
   private Boolean               allowInsecureHttp        = false;
   private String                policySpec               = PolicyFormat.DEFAULT_SPEC;
   private String                policyVersion            = PolicyFormat.DEFAULT_VERSION;
   private String                policyAttribute          = PolicyFormat.DEFAULT_ATTRIBUTE;
   private String                policyClaim              = PolicyFormat.DEFAULT_CLAIM;
   private Boolean               policyTwoPersonApproval  = false;



   /*******************************************************************************
    ** Collect configuration errors. Never throws; null-safe for a partially
    ** built QInstance.
    *******************************************************************************/
   @Override
   public void validate(QInstance qInstance, List<String> errors)
   {
      if(!StringUtils.hasContent(baseUrl))
      {
         errors.add("baseUrl is required (the Authentik host root, e.g. https://auth.example.com)");
      }
      else
      {
         try
         {
            URI uri = URI.create(baseUrl);
            if(uri.getScheme() == null || !(uri.getScheme().equals("https") || uri.getScheme().equals("http")) || uri.getHost() == null)
            {
               errors.add("baseUrl must be an absolute http(s) URL: " + baseUrl);
            }
            else if(uri.getScheme().equals("http") && !Boolean.TRUE.equals(allowInsecureHttp) && !isLoopback(uri.getHost()))
            {
               errors.add("baseUrl must use https (the API token would travel in cleartext); http is allowed only for localhost or with allowInsecureHttp: " + baseUrl);
            }
            else if(uri.getPath() != null && uri.getPath().contains("/api/v3"))
            {
               errors.add("baseUrl must be the host root; /api/v3 is appended by the qbit: " + baseUrl);
            }
         }
         catch(IllegalArgumentException e)
         {
            errors.add("baseUrl is not a valid URL: " + baseUrl);
         }
      }

      if(!StringUtils.hasContent(getResolvedApiToken()))
      {
         errors.add("apiToken is required (usually ${env.AUTHENTIK_API_TOKEN}) and resolved to an empty value");
      }

      if(!StringUtils.hasContent(appKey) || !APP_KEY_PATTERN.matcher(appKey).matches())
      {
         errors.add("appKey is required: lower-case letters, digits and dashes, e.g. my-app-admin");
      }

      if(tableNamePrefix != null && !tableNamePrefix.isEmpty() && !PREFIX_PATTERN.matcher(tableNamePrefix).matches())
      {
         errors.add("tableNamePrefix must start with a letter and contain only letters and digits: " + tableNamePrefix);
      }

      if(StringUtils.hasContent(groupScopeNamePrefix))
      {
         errors.add("groupScopeNamePrefix is not available in this release of qbit-authentik");
      }

      Set<AuthentikFeature> requested = features == null ? EnumSet.noneOf(AuthentikFeature.class) : features;
      if(!requested.contains(AuthentikFeature.READ))
      {
         errors.add("feature READ is required");
      }
      for(AuthentikFeature feature : requested)
      {
         if(!AVAILABLE_FEATURES.contains(feature))
         {
            errors.add("feature " + feature + " is not available in this release of qbit-authentik (available: " + AVAILABLE_FEATURES + ")");
         }
      }

      boolean writes = requested.stream().anyMatch(WRITE_FEATURES::contains);
      if(writes || StringUtils.hasContent(localBackendName))
      {
         if(!StringUtils.hasContent(localBackendName))
         {
            errors.add("features that change Authentik data need localBackendName (an RDBMS backend of the instance, for the audit trail)");
         }
         else if(qInstance != null && qInstance.getBackends() != null && qInstance.getBackend(localBackendName) == null)
         {
            errors.add("localBackendName: backend not found: " + localBackendName);
         }
      }

      if((requested.contains(AuthentikFeature.USERS) || requested.contains(AuthentikFeature.CREDENTIALS)) && !StringUtils.hasContent(recoveryEmailStage))
      {
         errors.add("features USERS and CREDENTIALS need recoveryEmailStage");
      }

      if(requested.contains(AuthentikFeature.DELETE) && !requested.contains(AuthentikFeature.USERS) && !requested.contains(AuthentikFeature.GROUPS))
      {
         errors.add("feature DELETE needs USERS or GROUPS");
      }

      if(requested.contains(AuthentikFeature.POLICIES) && !requested.contains(AuthentikFeature.GROUPS))
      {
         errors.add("feature POLICIES needs GROUPS");
      }

      if(requested.contains(AuthentikFeature.WEBHOOK) && !StringUtils.hasContent(getResolvedWebhookSecret()))
      {
         errors.add("feature WEBHOOK needs webhookSecret");
      }

      for(String subject : getResolvedBootstrapSubjects())
      {
         if(subject.contains("@"))
         {
            errors.add("bootstrapOperatorSubjects must be immutable ids (the token sub, or the Authentik user pk or uuid), never emails: users can change their own email");
            break;
         }
      }

      for(Integer value : new Integer[] { throttleRequestsPerSecond, throttleBurst, listCacheTtlSeconds, groupCacheTtlSeconds, connectTimeoutMillis, socketTimeoutMillis })
      {
         if(value == null || value < 0)
         {
            errors.add("throttle, cache and timeout settings must be non-negative numbers");
            break;
         }
      }
      String policyProblem = getPolicyFormat().problem();
      if(policyProblem != null)
      {
         errors.add(policyProblem);
      }

      if(throttleRequestsPerSecond != null && throttleRequestsPerSecond == 0)
      {
         errors.add("throttleRequestsPerSecond must be at least 1");
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static boolean isLoopback(String host)
   {
      return ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "[::1]".equals(host) || "::1".equals(host));
   }



   /*******************************************************************************
    ** Getter for allowInsecureHttp
    *******************************************************************************/
   public Boolean getAllowInsecureHttp()
   {
      return (this.allowInsecureHttp);
   }



   /*******************************************************************************
    ** Fluent setter for allowInsecureHttp (plain http to a non-loopback host;
    ** for tests and private networks only)
    *******************************************************************************/
   public AuthentikQBitConfig withAllowInsecureHttp(Boolean allowInsecureHttp)
   {
      this.allowInsecureHttp = allowInsecureHttp;
      return (this);
   }



   /*******************************************************************************
    ** Prefix a non-table component name (app, widget, backend, process) with the
    ** tableNamePrefix (camel-cased join), e.g. "authentikAdmin". Table names use
    ** applyTablePrefix instead.
    *******************************************************************************/
   public String applyPrefix(String name)
   {
      if(!StringUtils.hasContent(tableNamePrefix))
      {
         return (name);
      }
      return (tableNamePrefix + Character.toUpperCase(name.charAt(0)) + name.substring(1));
   }



   /*******************************************************************************
    ** Prefix a table name: lowercase snake_case, joined with "_", e.g. "user" ->
    ** "authentik_user", "groupMember" -> "authentik_group_member" (owner naming
    ** rule, 2026-10-12: table names are lowercase with "_", prefixed with the
    ** qbit's name).
    *******************************************************************************/
   public String applyTablePrefix(String name)
   {
      String snakeName = toSnakeCase(name);
      if(!StringUtils.hasContent(tableNamePrefix))
      {
         return (snakeName);
      }
      return (toSnakeCase(tableNamePrefix) + "_" + snakeName);
   }



   /*******************************************************************************
    ** camelCase (or PascalCase) to lowercase snake_case: "groupMember" ->
    ** "group_member", "myAuth" -> "my_auth". Already-snake input is unchanged.
    *******************************************************************************/
   public static String toSnakeCase(String name)
   {
      if(name == null)
      {
         return (null);
      }

      StringBuilder rs = new StringBuilder(name.length() + 8);
      for(int i = 0; i < name.length(); i++)
      {
         char c = name.charAt(i);
         if(Character.isUpperCase(c))
         {
            boolean afterLowerOrDigit = i > 0 && (Character.isLowerCase(name.charAt(i - 1)) || Character.isDigit(name.charAt(i - 1)));
            boolean endOfAcronym      = i > 0 && i + 1 < name.length() && Character.isUpperCase(name.charAt(i - 1)) && Character.isLowerCase(name.charAt(i + 1));
            if((afterLowerOrDigit || endOfAcronym) && rs.length() > 0 && rs.charAt(rs.length() - 1) != '_')
            {
               rs.append('_');
            }
            rs.append(Character.toLowerCase(c));
         }
         else
         {
            rs.append(c);
         }
      }
      return (rs.toString());
   }



   /*******************************************************************************
    ** Name of the API backend the qbit produces.
    *******************************************************************************/
   @JsonIgnore
   public String getApiBackendName()
   {
      return (applyPrefix("api"));
   }



   /*******************************************************************************
    ** The API root: baseUrl without a trailing slash, plus /api/v3.
    *******************************************************************************/
   @JsonIgnore
   public String getApiRoot()
   {
      String root = baseUrl == null ? "" : baseUrl.trim();
      while(root.endsWith("/"))
      {
         root = root.substring(0, root.length() - 1);
      }
      return (root + "/api/v3");
   }



   /*******************************************************************************
    ** The service account's username: explicit, or qqq-{appKey}-idadmin.
    *******************************************************************************/
   @JsonIgnore
   public String getEffectiveServiceAccountUsername()
   {
      return (StringUtils.hasContent(serviceAccountUsername) ? serviceAccountUsername : "qqq-" + appKey + "-idadmin");
   }



   /*******************************************************************************
    ** The API token with ${env.X} / ${prop.X} references resolved.
    *******************************************************************************/
   @JsonIgnore
   public String getResolvedApiToken()
   {
      return (resolve(apiToken));
   }



   /*******************************************************************************
    ** The webhook secret with references resolved.
    *******************************************************************************/
   @JsonIgnore
   public String getResolvedWebhookSecret()
   {
      return (resolve(webhookSecret));
   }



   /*******************************************************************************
    ** Bootstrap operator subjects, resolved and split on commas. Each is an
    ** IMMUTABLE identifier (the token's sub, or the Authentik user pk or uuid);
    ** never an email, because users can change their own email.
    *******************************************************************************/
   @JsonIgnore
   public Set<String> getResolvedBootstrapSubjects()
   {
      Set<String> rs       = new LinkedHashSet<>();
      String      resolved = resolve(bootstrapOperatorSubjects);
      if(StringUtils.hasContent(resolved))
      {
         for(String part : resolved.split(","))
         {
            if(StringUtils.hasContent(part))
            {
               rs.add(part.trim());
            }
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Whether a feature is enabled.
    *******************************************************************************/
   public boolean hasFeature(AuthentikFeature feature)
   {
      return (features != null && features.contains(feature));
   }



   /*******************************************************************************
    ** Resolve ${env.X} style references; a reference to an unset variable
    ** resolves to null rather than to its literal text.
    *******************************************************************************/
   static String resolve(String value)
   {
      if(value == null)
      {
         return (null);
      }
      String resolved = new QMetaDataVariableInterpreter().interpret(value);
      if(resolved != null && resolved.startsWith("${") && resolved.endsWith("}"))
      {
         return (null);
      }
      return (resolved);
   }



   /*******************************************************************************
    ** Never print secrets.
    *******************************************************************************/
   @Override
   public String toString()
   {
      return ("AuthentikQBitConfig{baseUrl=" + baseUrl + ", appKey=" + appKey + ", tableNamePrefix=" + tableNamePrefix
         + ", features=" + features + ", readOnly=" + readOnly + ", apiToken=" + (StringUtils.hasContent(apiToken) ? "******" : "(unset)") + "}");
   }



   /*******************************************************************************
    ** Getter for baseUrl
    *******************************************************************************/
   public String getBaseUrl()
   {
      return (this.baseUrl);
   }



   /*******************************************************************************
    ** Setter for baseUrl
    *******************************************************************************/
   public void setBaseUrl(String baseUrl)
   {
      this.baseUrl = baseUrl;
   }



   /*******************************************************************************
    ** Fluent setter for baseUrl
    *******************************************************************************/
   public AuthentikQBitConfig withBaseUrl(String baseUrl)
   {
      this.baseUrl = baseUrl;
      return (this);
   }



   /*******************************************************************************
    ** Getter for apiToken (the raw, possibly ${env.X}, value). Never serialized.
    *******************************************************************************/
   @JsonIgnore
   public String getApiToken()
   {
      return (this.apiToken);
   }



   /*******************************************************************************
    ** Setter for apiToken
    *******************************************************************************/
   public void setApiToken(String apiToken)
   {
      this.apiToken = apiToken;
   }



   /*******************************************************************************
    ** Fluent setter for apiToken
    *******************************************************************************/
   public AuthentikQBitConfig withApiToken(String apiToken)
   {
      this.apiToken = apiToken;
      return (this);
   }



   /*******************************************************************************
    ** Getter for appKey
    *******************************************************************************/
   public String getAppKey()
   {
      return (this.appKey);
   }



   /*******************************************************************************
    ** Setter for appKey
    *******************************************************************************/
   public void setAppKey(String appKey)
   {
      this.appKey = appKey;
   }



   /*******************************************************************************
    ** Fluent setter for appKey
    *******************************************************************************/
   public AuthentikQBitConfig withAppKey(String appKey)
   {
      this.appKey = appKey;
      return (this);
   }



   /*******************************************************************************
    ** Getter for tableNamePrefix
    *******************************************************************************/
   public String getTableNamePrefix()
   {
      return (this.tableNamePrefix);
   }



   /*******************************************************************************
    ** Setter for tableNamePrefix
    *******************************************************************************/
   public void setTableNamePrefix(String tableNamePrefix)
   {
      this.tableNamePrefix = tableNamePrefix;
   }



   /*******************************************************************************
    ** Fluent setter for tableNamePrefix
    *******************************************************************************/
   public AuthentikQBitConfig withTableNamePrefix(String tableNamePrefix)
   {
      this.tableNamePrefix = tableNamePrefix;
      return (this);
   }



   /*******************************************************************************
    ** Getter for features
    *******************************************************************************/
   public Set<AuthentikFeature> getFeatures()
   {
      return (this.features);
   }



   /*******************************************************************************
    ** Setter for features
    *******************************************************************************/
   public void setFeatures(Set<AuthentikFeature> features)
   {
      this.features = features;
   }



   /*******************************************************************************
    ** Fluent setter for features
    *******************************************************************************/
   public AuthentikQBitConfig withFeatures(Set<AuthentikFeature> features)
   {
      this.features = features;
      return (this);
   }



   /*******************************************************************************
    ** Getter for readOnly
    *******************************************************************************/
   public Boolean getReadOnly()
   {
      return (this.readOnly);
   }



   /*******************************************************************************
    ** Setter for readOnly
    *******************************************************************************/
   public void setReadOnly(Boolean readOnly)
   {
      this.readOnly = readOnly;
   }



   /*******************************************************************************
    ** Fluent setter for readOnly
    *******************************************************************************/
   public AuthentikQBitConfig withReadOnly(Boolean readOnly)
   {
      this.readOnly = readOnly;
      return (this);
   }



   /*******************************************************************************
    ** Getter for serviceAccountUsername
    *******************************************************************************/
   public String getServiceAccountUsername()
   {
      return (this.serviceAccountUsername);
   }



   /*******************************************************************************
    ** Fluent setter for serviceAccountUsername
    *******************************************************************************/
   public AuthentikQBitConfig withServiceAccountUsername(String serviceAccountUsername)
   {
      this.serviceAccountUsername = serviceAccountUsername;
      return (this);
   }



   /*******************************************************************************
    ** Getter for userScopePathStartsWith
    *******************************************************************************/
   public String getUserScopePathStartsWith()
   {
      return (this.userScopePathStartsWith);
   }



   /*******************************************************************************
    ** Fluent setter for userScopePathStartsWith
    *******************************************************************************/
   public AuthentikQBitConfig withUserScopePathStartsWith(String userScopePathStartsWith)
   {
      this.userScopePathStartsWith = userScopePathStartsWith;
      return (this);
   }



   /*******************************************************************************
    ** Getter for userScopeGroupNames
    *******************************************************************************/
   public List<String> getUserScopeGroupNames()
   {
      return (this.userScopeGroupNames);
   }



   /*******************************************************************************
    ** Fluent setter for userScopeGroupNames
    *******************************************************************************/
   public AuthentikQBitConfig withUserScopeGroupNames(List<String> userScopeGroupNames)
   {
      this.userScopeGroupNames = userScopeGroupNames;
      return (this);
   }



   /*******************************************************************************
    ** Getter for groupScopeNamePrefix
    *******************************************************************************/
   public String getGroupScopeNamePrefix()
   {
      return (this.groupScopeNamePrefix);
   }



   /*******************************************************************************
    ** Fluent setter for groupScopeNamePrefix
    *******************************************************************************/
   public AuthentikQBitConfig withGroupScopeNamePrefix(String groupScopeNamePrefix)
   {
      this.groupScopeNamePrefix = groupScopeNamePrefix;
      return (this);
   }



   /*******************************************************************************
    ** Getter for protectedUsernames
    *******************************************************************************/
   public List<String> getProtectedUsernames()
   {
      return (this.protectedUsernames);
   }



   /*******************************************************************************
    ** Fluent setter for protectedUsernames
    *******************************************************************************/
   public AuthentikQBitConfig withProtectedUsernames(List<String> protectedUsernames)
   {
      this.protectedUsernames = protectedUsernames;
      return (this);
   }



   /*******************************************************************************
    ** Getter for bootstrapOperatorSubjects (raw value)
    *******************************************************************************/
   public String getBootstrapOperatorSubjects()
   {
      return (this.bootstrapOperatorSubjects);
   }



   /*******************************************************************************
    ** Fluent setter for bootstrapOperatorSubjects (comma-separated emails or ${env.X})
    *******************************************************************************/
   public AuthentikQBitConfig withBootstrapOperatorSubjects(String bootstrapOperatorSubjects)
   {
      this.bootstrapOperatorSubjects = bootstrapOperatorSubjects;
      return (this);
   }



   /*******************************************************************************
    ** Getter for applicationsInScope
    *******************************************************************************/
   public List<String> getApplicationsInScope()
   {
      return (this.applicationsInScope);
   }



   /*******************************************************************************
    ** Fluent setter for applicationsInScope. Explicit slugs are required:
    ** Authentik lists to a non-superuser only the applications that user can
    ** itself access, so the qbit cannot discover them (phase 0 finding).
    *******************************************************************************/
   public AuthentikQBitConfig withApplicationsInScope(List<String> applicationsInScope)
   {
      this.applicationsInScope = applicationsInScope;
      return (this);
   }



   /*******************************************************************************
    ** Getter for localBackendName: the RDBMS backend holding the qbit's own
    ** tables (admin actions, approval requests).
    *******************************************************************************/
   public String getLocalBackendName()
   {
      return (this.localBackendName);
   }



   /*******************************************************************************
    ** Fluent setter for localBackendName
    *******************************************************************************/
   public AuthentikQBitConfig withLocalBackendName(String localBackendName)
   {
      this.localBackendName = localBackendName;
      return (this);
   }



   /*******************************************************************************
    ** Getter for twoPersonApproval: whether adding authentik.* permissions to a
    ** group needs a second person (authentik.approve) to approve it.
    *******************************************************************************/
   public Boolean getTwoPersonApproval()
   {
      return (this.twoPersonApproval);
   }



   /*******************************************************************************
    ** Fluent setter for twoPersonApproval
    *******************************************************************************/
   public AuthentikQBitConfig withTwoPersonApproval(Boolean twoPersonApproval)
   {
      this.twoPersonApproval = twoPersonApproval;
      return (this);
   }



   /*******************************************************************************
    ** Getter for linkPrefix: the path prefix of table and record links the home
    ** page renders (the Next UI serves tables at /app/{table}).
    *******************************************************************************/
   public String getLinkPrefix()
   {
      return (this.linkPrefix);
   }



   /*******************************************************************************
    ** Fluent setter for linkPrefix
    *******************************************************************************/
   public AuthentikQBitConfig withLinkPrefix(String linkPrefix)
   {
      this.linkPrefix = linkPrefix;
      return (this);
   }



   /*******************************************************************************
    ** Getter for schedulerName (optional; runs the reconcile/attention checks)
    *******************************************************************************/
   public String getSchedulerName()
   {
      return (this.schedulerName);
   }



   /*******************************************************************************
    ** Fluent setter for schedulerName
    *******************************************************************************/
   public AuthentikQBitConfig withSchedulerName(String schedulerName)
   {
      this.schedulerName = schedulerName;
      return (this);
   }



   /*******************************************************************************
    ** Getter for recoveryEmailStage
    *******************************************************************************/
   public String getRecoveryEmailStage()
   {
      return (this.recoveryEmailStage);
   }



   /*******************************************************************************
    ** Fluent setter for recoveryEmailStage
    *******************************************************************************/
   public AuthentikQBitConfig withRecoveryEmailStage(String recoveryEmailStage)
   {
      this.recoveryEmailStage = recoveryEmailStage;
      return (this);
   }



   /*******************************************************************************
    ** Getter for invitationFlow
    *******************************************************************************/
   public String getInvitationFlow()
   {
      return (this.invitationFlow);
   }



   /*******************************************************************************
    ** Fluent setter for invitationFlow
    *******************************************************************************/
   public AuthentikQBitConfig withInvitationFlow(String invitationFlow)
   {
      this.invitationFlow = invitationFlow;
      return (this);
   }



   /*******************************************************************************
    ** Getter for newUserPath
    *******************************************************************************/
   public String getNewUserPath()
   {
      return (this.newUserPath);
   }



   /*******************************************************************************
    ** Fluent setter for newUserPath
    *******************************************************************************/
   public AuthentikQBitConfig withNewUserPath(String newUserPath)
   {
      this.newUserPath = newUserPath;
      return (this);
   }



   /*******************************************************************************
    ** Getter for webhookSecret (raw value). Never serialized.
    *******************************************************************************/
   @JsonIgnore
   public String getWebhookSecret()
   {
      return (this.webhookSecret);
   }



   /*******************************************************************************
    ** Fluent setter for webhookSecret
    *******************************************************************************/
   public AuthentikQBitConfig withWebhookSecret(String webhookSecret)
   {
      this.webhookSecret = webhookSecret;
      return (this);
   }



   /*******************************************************************************
    ** Getter for throttleRequestsPerSecond
    *******************************************************************************/
   public Integer getThrottleRequestsPerSecond()
   {
      return (this.throttleRequestsPerSecond);
   }



   /*******************************************************************************
    ** Fluent setter for throttleRequestsPerSecond
    *******************************************************************************/
   public AuthentikQBitConfig withThrottleRequestsPerSecond(Integer throttleRequestsPerSecond)
   {
      this.throttleRequestsPerSecond = throttleRequestsPerSecond;
      return (this);
   }



   /*******************************************************************************
    ** Getter for throttleBurst
    *******************************************************************************/
   public Integer getThrottleBurst()
   {
      return (this.throttleBurst);
   }



   /*******************************************************************************
    ** Fluent setter for throttleBurst
    *******************************************************************************/
   public AuthentikQBitConfig withThrottleBurst(Integer throttleBurst)
   {
      this.throttleBurst = throttleBurst;
      return (this);
   }



   /*******************************************************************************
    ** Getter for bulkPacingMillis
    *******************************************************************************/
   public Integer getBulkPacingMillis()
   {
      return (this.bulkPacingMillis);
   }



   /*******************************************************************************
    ** Fluent setter for bulkPacingMillis
    *******************************************************************************/
   public AuthentikQBitConfig withBulkPacingMillis(Integer bulkPacingMillis)
   {
      this.bulkPacingMillis = bulkPacingMillis;
      return (this);
   }



   /*******************************************************************************
    ** Getter for listCacheTtlSeconds
    *******************************************************************************/
   public Integer getListCacheTtlSeconds()
   {
      return (this.listCacheTtlSeconds);
   }



   /*******************************************************************************
    ** Fluent setter for listCacheTtlSeconds (0 disables the list cache)
    *******************************************************************************/
   public AuthentikQBitConfig withListCacheTtlSeconds(Integer listCacheTtlSeconds)
   {
      this.listCacheTtlSeconds = listCacheTtlSeconds;
      return (this);
   }



   /*******************************************************************************
    ** Getter for groupCacheTtlSeconds
    *******************************************************************************/
   public Integer getGroupCacheTtlSeconds()
   {
      return (this.groupCacheTtlSeconds);
   }



   /*******************************************************************************
    ** Fluent setter for groupCacheTtlSeconds (0 disables the group cache)
    *******************************************************************************/
   public AuthentikQBitConfig withGroupCacheTtlSeconds(Integer groupCacheTtlSeconds)
   {
      this.groupCacheTtlSeconds = groupCacheTtlSeconds;
      return (this);
   }



   /*******************************************************************************
    ** Getter for connectTimeoutMillis
    *******************************************************************************/
   public Integer getConnectTimeoutMillis()
   {
      return (this.connectTimeoutMillis);
   }



   /*******************************************************************************
    ** Fluent setter for connectTimeoutMillis
    *******************************************************************************/
   public AuthentikQBitConfig withConnectTimeoutMillis(Integer connectTimeoutMillis)
   {
      this.connectTimeoutMillis = connectTimeoutMillis;
      return (this);
   }



   /*******************************************************************************
    ** Getter for socketTimeoutMillis
    *******************************************************************************/
   public Integer getSocketTimeoutMillis()
   {
      return (this.socketTimeoutMillis);
   }



   /*******************************************************************************
    ** Fluent setter for socketTimeoutMillis
    *******************************************************************************/
   public AuthentikQBitConfig withSocketTimeoutMillis(Integer socketTimeoutMillis)
   {
      this.socketTimeoutMillis = socketTimeoutMillis;
      return (this);
   }



   /*******************************************************************************
    ** Getter for expectedServerVersion
    *******************************************************************************/
   public String getExpectedServerVersion()
   {
      return (this.expectedServerVersion);
   }



   /*******************************************************************************
    ** Fluent setter for expectedServerVersion (major.minor, e.g. 2026.8)
    *******************************************************************************/
   public AuthentikQBitConfig withExpectedServerVersion(String expectedServerVersion)
   {
      this.expectedServerVersion = expectedServerVersion;
      return (this);
   }



   /*******************************************************************************
    ** Getter for policySpec: the PolicySpec this app accepts and writes (docs/POLICY-FORMAT.md).
    *******************************************************************************/
   public String getPolicySpec()
   {
      return (this.policySpec);
   }



   /*******************************************************************************
    ** Fluent setter for policySpec
    *******************************************************************************/
   public AuthentikQBitConfig withPolicySpec(String policySpec)
   {
      this.policySpec = policySpec;
      return (this);
   }



   /*******************************************************************************
    ** Getter for policyVersion: the one supported PolicyVersion (semver).
    *******************************************************************************/
   public String getPolicyVersion()
   {
      return (this.policyVersion);
   }



   /*******************************************************************************
    ** Fluent setter for policyVersion
    *******************************************************************************/
   public AuthentikQBitConfig withPolicyVersion(String policyVersion)
   {
      this.policyVersion = policyVersion;
      return (this);
   }



   /*******************************************************************************
    ** Getter for policyAttribute: the Authentik group attribute that holds a group's policy document.
    *******************************************************************************/
   public String getPolicyAttribute()
   {
      return (this.policyAttribute);
   }



   /*******************************************************************************
    ** Fluent setter for policyAttribute
    *******************************************************************************/
   public AuthentikQBitConfig withPolicyAttribute(String policyAttribute)
   {
      this.policyAttribute = policyAttribute;
      return (this);
   }



   /*******************************************************************************
    ** Getter for policyClaim: the token claim that holds the merged policy document.
    *******************************************************************************/
   public String getPolicyClaim()
   {
      return (this.policyClaim);
   }



   /*******************************************************************************
    ** Fluent setter for policyClaim
    *******************************************************************************/
   public AuthentikQBitConfig withPolicyClaim(String policyClaim)
   {
      this.policyClaim = policyClaim;
      return (this);
   }



   /*******************************************************************************
    ** Getter for policyTwoPersonApproval: whether every policy save needs a second person (authentik.approve).
    *******************************************************************************/
   public Boolean getPolicyTwoPersonApproval()
   {
      return (this.policyTwoPersonApproval);
   }



   /*******************************************************************************
    ** Fluent setter for policyTwoPersonApproval
    *******************************************************************************/
   public AuthentikQBitConfig withPolicyTwoPersonApproval(Boolean policyTwoPersonApproval)
   {
      this.policyTwoPersonApproval = policyTwoPersonApproval;
      return (this);
   }



   /*******************************************************************************
    ** The policy names (spec, version, attribute, claim) as one value.
    *******************************************************************************/
   @JsonIgnore
   public PolicyFormat getPolicyFormat()
   {
      return (new PolicyFormat(policySpec, policyVersion, policyAttribute, policyClaim));
   }

}
