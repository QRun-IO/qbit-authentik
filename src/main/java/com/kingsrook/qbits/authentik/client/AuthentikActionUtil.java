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

package com.kingsrook.qbits.authentik.client;


import java.io.Serializable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.permissions.EffectivePermissionResolver;
import com.kingsrook.qbits.authentik.permissions.GroupGraph;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qbits.authentik.security.WriteAuthorization;
import com.kingsrook.qqq.backend.core.actions.customizers.QCodeLoader;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryOutput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateOutput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.utils.SleepUtils;
import com.kingsrook.qqq.backend.core.utils.StringUtils;
import com.kingsrook.qqq.backend.module.api.actions.BaseAPIActionUtil;
import com.kingsrook.qqq.backend.module.api.actions.QHttpResponse;
import com.kingsrook.qqq.backend.module.api.model.OutboundAPILog;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;
import org.apache.http.Header;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** The qbit's Authentik API client, as a qqq-backend-module-api action util
 ** (DESIGN.md sections 2.4 and 6.1).
 **
 ** - Bearer authentication with the service account's API token.
 ** - Page-based paging (page / page_size, max 100), count from
 **   pagination.count with page_size=1.
 ** - QQQ filters mapped by AuthentikFilterMapper; unsupported ones rejected.
 ** - Every call passes AuthentikGuard first, then the shared token-bucket
 **   throttle (Authentik does not throttle authenticated calls).
 ** - Logs carry method, path and status only. Request query strings (search
 **   terms are PII), bodies of sensitive endpoints and successful GET bodies
 **   are never logged or stored; anything stored is passed through
 **   AuthentikRedactor.
 *******************************************************************************/
public class AuthentikActionUtil extends BaseAPIActionUtil
{
   private static final QLogger LOG = QLogger.getLogger(AuthentikActionUtil.class);

   public static final int MAX_PAGE_SIZE = 100;

   private static final int MAX_RETRIES          = 3;
   private static final int INITIAL_BACKOFF_MS   = 250;
   private static final int MAX_RETRY_AFTER_SECS = 30;

   private static final AtomicBoolean VERSION_CHECKED = new AtomicBoolean(false);

   /** Maximum memberships / groups read by one sweep (bounded, never silently: see memberships()). */
   public static final int MAX_SWEEP_OBJECTS = 20_000;

   /** Display value for derived fields when the group graph cannot be read. */
   public static final String UNAVAILABLE = "Unavailable (Authentik groups could not be read)";

   private EffectivePermissionResolver resolverForCall;



   /*******************************************************************************
    ** A client for a qbit API backend of the current QInstance, for code that
    ** is not a table action (widgets, the drift report). Honours the backend's
    ** configured action util class (tests swap it).
    *******************************************************************************/
   public static AuthentikActionUtil forBackend(String backendName) throws QException
   {
      if(QContext.getQInstance() == null || !(QContext.getQInstance().getBackend(backendName) instanceof APIBackendMetaData backend))
      {
         throw (new QException("No Authentik API backend named " + backendName));
      }
      BaseAPIActionUtil util = QCodeLoader.getAdHoc(BaseAPIActionUtil.class, backend.getActionUtil());
      util.setBackendMetaData(backend);
      return ((AuthentikActionUtil) util);
   }



   /*******************************************************************************
    ** The runtime for the backend this util serves.
    *******************************************************************************/
   protected AuthentikRuntime runtime()
   {
      return (AuthentikRuntime.forBackend(backendMetaData.getName()));
   }



   /*******************************************************************************
    ** The spec for a table, or an exception for a table the qbit didn't produce.
    *******************************************************************************/
   protected AuthentikTableSpec spec(QTableMetaData table) throws QException
   {
      AuthentikTableSpec spec = runtime().getSpec(table.getName());
      if(spec == null)
      {
         throw (new QException("Table " + table.getName() + " is not an Authentik qbit table"));
      }
      return (spec);
   }



   /*******************************************************************************
    ** Count: one request with page_size=1, reading pagination.count.
    *******************************************************************************/
   @Override
   public CountOutput doCount(QTableMetaData table, CountInput countInput) throws QException
   {
      AuthentikTableSpec spec = spec(table);
      runtime().getGuard().checkRead(spec);

      CountOutput output = new CountOutput();
      if(spec.isVirtual())
      {
         output.setCount(memberships(spec, countInput.getFilter()).size());
         output.setDistinctCount(output.getCount());
         return (output);
      }

      AuthentikFilterMapper.MappedFilter mapped = map(spec, countInput.getFilter());
      if(mapped.isKeyLookup())
      {
         output.setCount(fetchByKeys(table, spec, mapped.keyLookup(), null).size());
         output.setDistinctCount(output.getCount());
         return (output);
      }

      JSONObject page = getJson(listUrl(spec, mapped, 1, 1));
      output.setCount(pagination(page).optInt("count", 0));
      output.setDistinctCount(output.getCount());
      return (output);
   }



   /*******************************************************************************
    ** Get one record by key. Out-of-scope or missing records return no record.
    *******************************************************************************/
   @Override
   public GetOutput doGet(QTableMetaData table, GetInput getInput) throws QException
   {
      AuthentikTableSpec spec = spec(table);
      runtime().getGuard().checkRead(spec);

      GetOutput output = new GetOutput();
      if(getInput.getPrimaryKey() == null)
      {
         throw (new QUserFacingException(spec.getLabel() + " can only be fetched by id."));
      }

      if(spec.isVirtual())
      {
         List<JSONObject> rows = memberships(spec, new QQueryFilter(new com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria(spec.getKeyFieldName(),
            com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator.EQUALS, getInput.getPrimaryKey())));
         if(!rows.isEmpty())
         {
            output.setRecord(toRecord(spec, rows.get(0), runtime().getGuard().maySeeSensitive()));
         }
         return (output);
      }

      JSONObject object = getObject(spec, getInput.getPrimaryKey());
      if(object != null && isVisible(spec, object))
      {
         output.setRecord(toRecord(spec, object, runtime().getGuard().maySeeSensitive()));
      }
      return (output);
   }



   /*******************************************************************************
    ** Query with page-based paging.
    *******************************************************************************/
   @Override
   public QueryOutput doQuery(QTableMetaData table, QueryInput queryInput) throws QException
   {
      AuthentikTableSpec spec = spec(table);
      runtime().getGuard().checkRead(spec);

      QueryOutput  output    = new QueryOutput(queryInput);
      QQueryFilter filter    = queryInput.getFilter();
      boolean      sensitive = runtime().getGuard().maySeeSensitive();

      Integer limit = filter == null ? null : filter.getLimit();
      int     skip  = filter == null || filter.getSkip() == null ? 0 : filter.getSkip();

      if(limit != null && limit <= 0)
      {
         return (output);
      }

      if(spec.isVirtual())
      {
         List<JSONObject> rows  = memberships(spec, filter);
         int              added = 0;
         for(int i = skip; i < rows.size() && (limit == null || added < limit); i++)
         {
            output.addRecord(toRecord(spec, rows.get(i), sensitive));
            added++;
         }
         return (output);
      }

      AuthentikFilterMapper.MappedFilter mapped = map(spec, filter);

      if(mapped.isKeyLookup())
      {
         List<JSONObject> objects = fetchByKeys(table, spec, mapped.keyLookup(), limit);
         int              added   = 0;
         for(int i = skip; i < objects.size() && (limit == null || added < limit); i++)
         {
            output.addRecord(toRecord(spec, objects.get(i), sensitive));
            added++;
         }
         return (output);
      }

      int pageSize;
      int page;
      int offset;
      if(limit != null && limit > 0 && limit <= MAX_PAGE_SIZE && skip % limit == 0)
      {
         pageSize = limit;
         page = skip / limit + 1;
         offset = 0;
      }
      else
      {
         pageSize = MAX_PAGE_SIZE;
         page = skip / MAX_PAGE_SIZE + 1;
         offset = skip % MAX_PAGE_SIZE;
      }

      int collected = 0;
      while(true)
      {
         JSONObject response = getJson(listUrl(spec, mapped, page, pageSize));
         JSONArray  results  = response.optJSONArray("results");
         if(results == null || results.isEmpty())
         {
            return (output);
         }

         for(int i = offset; i < results.length(); i++)
         {
            JSONObject object = results.getJSONObject(i);
            if(!isVisible(spec, object))
            {
               continue;
            }
            output.addRecord(toRecord(spec, object, sensitive));
            collected++;
            if(limit != null && collected >= limit)
            {
               return (output);
            }
         }
         offset = 0;

         int totalPages = pagination(response).optInt("total_pages", page);
         if(page >= totalPages || queryInput.getAsyncJobCallback().wasCancelRequested())
         {
            return (output);
         }
         page++;
      }
   }



   /*******************************************************************************
    ** Writes go through the guard, which refuses them in this release.
    *******************************************************************************/
   @Override
   public InsertOutput doInsert(QTableMetaData table, InsertInput insertInput) throws QException
   {
      runtime().getGuard().checkWrite(spec(table), "insert");
      throw (new QPermissionDeniedException("Not available"));
   }



   /*******************************************************************************
    ** Writes go through the guard, which refuses them in this release.
    *******************************************************************************/
   @Override
   public UpdateOutput doUpdate(QTableMetaData table, UpdateInput updateInput) throws QException
   {
      runtime().getGuard().checkWrite(spec(table), "update");
      throw (new QPermissionDeniedException("Not available"));
   }



   /*******************************************************************************
    ** Writes go through the guard, which refuses them in this release.
    *******************************************************************************/
   @Override
   public DeleteOutput doDelete(QTableMetaData table, DeleteInput deleteInput) throws QException
   {
      runtime().getGuard().checkWrite(spec(table), "delete");
      throw (new QPermissionDeniedException("Not available"));
   }



   /*******************************************************************************
    ** Send a request that changes Authentik data. Needs the guard's
    ** authorization; every successful write drops the response and group caches.
    ** The path is relative to /api/v3. Returns the response body as JSON (an
    ** empty object for 204 / empty bodies); a missing target is an error.
    **
    ** @param method POST, PATCH or DELETE
    ** @param body   request body (null for none)
    *******************************************************************************/
   public JSONObject write(WriteAuthorization authorization, String method, String pathAndQuery, JSONObject body) throws QException
   {
      return (writeAs(token(), authorization, method, pathAndQuery, body));
   }



   /*******************************************************************************
    ** Explicit bearer for an authorized token action, through the same send seam.
    *******************************************************************************/
   public JSONObject writeAs(String bearer, WriteAuthorization authorization, String method, String pathAndQuery, JSONObject body) throws QException
   {
      if(authorization == null)
      {
         throw (new QPermissionDeniedException("Authentik data can only be changed through the guard."));
      }
      if(pathAndQuery == null || pathAndQuery.contains("..") || !pathAndQuery.startsWith("/"))
      {
         throw (new QException("Bad Authentik path"));
      }

      checkAuthorization(authorization);
      String url = runtime().getConfig().getApiRoot() + pathAndQuery;
      HttpRequestBase request = switch(method)
      {
         case "POST" -> new HttpPost(url);
         case "PATCH" -> new HttpPatch(url);
         case "DELETE" -> new HttpDelete(url);
         default -> throw (new QException("Unsupported write method " + method));
      };
      if(body != null && request instanceof HttpEntityEnclosingRequest entityRequest)
      {
         entityRequest.setEntity(new StringEntity(body.toString(), ContentType.APPLICATION_JSON));
      }

      try
      {
         QHttpResponse response = execute(request, bearer, false);
         if(response.getStatusCode() != null && response.getStatusCode() == 404)
         {
            throw (new QUserFacingException("Authentik no longer has that record (it may have been removed in the Authentik admin UI)."));
         }
         String content = response.getContent();
         return (content == null || content.isBlank() ? new JSONObject() : new JSONObject(content));
      }
      catch(JSONException e)
      {
         return (new JSONObject());
      }
      finally
      {
         runtime().invalidateCache();
      }
   }



   /*******************************************************************************
    ** Read token metadata or its new key as its owner; never use the read cache.
    *******************************************************************************/
   public JSONObject getAs(String bearer, WriteAuthorization auth, String path) throws QException
   {
      checkAuthorization(auth);
      if(path == null || !path.startsWith("/core/tokens/") || path.contains("..") || path.contains("?"))
      {
         throw (new QException("Bad token path"));
      }
      QHttpResponse response = execute(new HttpGet(runtime().getConfig().getApiRoot() + path), bearer, false);
      try
      {
         return (response.getStatusCode() == 404 ? null : new JSONObject(response.getContent()));
      }
      catch(JSONException e)
      {
         throw (new QUserFacingException("Authentik returned an invalid token response."));
      }
   }



   /*******************************************************************************
    ** Exchange through the shared throttle/send seam with no service bearer.
    *******************************************************************************/
   public JSONObject exchangeToken(WriteAuthorization auth, HttpPost request) throws QException
   {
      checkAuthorization(auth);
      if(!request.getURI().toString().equals(runtime().getConfig().getTokenEndpointUrl()))
      {
         throw (new QException("Bad token endpoint"));
      }
      try
      {
         return (new JSONObject(execute(request, null, true).getContent()));
      }
      catch(JSONException e)
      {
         throw (new QUserFacingException("Authentik refused to act as you (invalid_response)"));
      }
   }



   /*******************************************************************************
    ** Revalidate the authorization against the current session and config.
    *******************************************************************************/
   private void checkAuthorization(WriteAuthorization auth) throws QException
   {
      if(auth == null || !java.util.Objects.equals(auth.getOperator(), runtime().getGuard().operatorEmail()))
      {
         throw (new QPermissionDeniedException("Authentik data can only be changed through the guard."));
      }
      runtime().getGuard().authorize(com.kingsrook.qbits.authentik.admin.AdminAction.valueOf(auth.getAction()));
   }



   /*******************************************************************************
    ** Fetch a single Authentik object by key (null when it doesn't exist).
    ** No permission check: callers check first.
    *******************************************************************************/
   public JSONObject getObject(AuthentikTableSpec spec, Serializable key) throws QException
   {
      String keyText = String.valueOf(key).trim();
      if(keyText.isEmpty() || !keyText.matches("[A-Za-z0-9._:-]+") || keyText.contains(".."))
      {
         return (null);
      }

      try
      {
         URIBuilder builder = new URIBuilder(runtime().getConfig().getApiRoot() + spec.getPath() + keyText + "/");
         for(NameValuePair param : spec.getDefaultGetParams())
         {
            builder.addParameter(param.getName(), param.getValue());
         }
         return (getJsonOrNull(builder.build().toString()));
      }
      catch(java.net.URISyntaxException e)
      {
         throw (new QException("Bad Authentik URL", e));
      }
   }



   /*******************************************************************************
    ** GET an API path (relative to /api/v3, may include a query string) and
    ** parse it as a JSON object. Used by the resolver and health checks.
    *******************************************************************************/
   public JSONObject getApiJson(String pathAndQuery) throws QException
   {
      return (getJson(runtime().getConfig().getApiRoot() + pathAndQuery));
   }



   /*******************************************************************************
    ** GET an API path whose response is a bare JSON array (not paged), such as
    ** the MFA device list.
    *******************************************************************************/
   public JSONArray getApiArray(String pathAndQuery) throws QException
   {
      String url  = runtime().getConfig().getApiRoot() + pathAndQuery;
      String body = getBody(url, false);
      try
      {
         return (new JSONArray(body));
      }
      catch(JSONException e)
      {
         throw (new QException("Authentik returned an unexpected response for " + pathOf(url)));
      }
   }



   /*******************************************************************************
    ** Fetch every page of a list endpoint (relative path with query string,
    ** without page parameters). Bounded by maxObjects.
    *******************************************************************************/
   public List<JSONObject> getAllPages(String pathAndQuery, int maxObjects) throws QException
   {
      List<JSONObject> rs   = new ArrayList<>();
      int              page = 1;
      while(true)
      {
         String     separator = pathAndQuery.contains("?") ? "&" : "?";
         JSONObject response  = getApiJson(pathAndQuery + separator + "page=" + page + "&page_size=" + MAX_PAGE_SIZE);
         JSONArray  results   = response.optJSONArray("results");
         if(results == null || results.isEmpty())
         {
            return (rs);
         }
         for(int i = 0; i < results.length() && rs.size() < maxObjects; i++)
         {
            rs.add(results.getJSONObject(i));
         }
         if(rs.size() >= maxObjects || page >= pagination(response).optInt("total_pages", page))
         {
            return (rs);
         }
         page++;
      }
   }



   /*******************************************************************************
    ** The server's version (GET /admin/version/), or empty when unavailable.
    *******************************************************************************/
   public Optional<String> fetchServerVersion()
   {
      try
      {
         JSONObject version = getApiJson("/admin/version/");
         return (Optional.ofNullable(version.optString("version_current", null)));
      }
      catch(Exception e)
      {
         LOG.info("Could not read the Authentik server version", logPair("error", AuthentikRedactor.redactText(e.getMessage(), token())));
         return (Optional.empty());
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private AuthentikFilterMapper.MappedFilter map(AuthentikTableSpec spec, QQueryFilter filter) throws QException
   {
      AuthentikFilterMapper.MappedFilter mapped = runtime().getFilterMapper().map(spec, filter, runtime().getGuard().maySeeSensitive());
      if(spec.getRequiredFilterField() != null && !mapped.filteredFields().contains(spec.getRequiredFilterField()))
      {
         throw (new QUserFacingException(spec.getLabel() + " can only be listed with a filter on " + spec.getField(spec.getRequiredFilterField()).getLabel() + "."));
      }
      return (mapped);
   }



   /*******************************************************************************
    ** Build a list URL: mapped params, defaults, scope params, paging.
    *******************************************************************************/
   private String listUrl(AuthentikTableSpec spec, AuthentikFilterMapper.MappedFilter mapped, int page, int pageSize) throws QException
   {
      try
      {
         URIBuilder builder = new URIBuilder(runtime().getConfig().getApiRoot() + spec.getPath());
         List<String> usedNames = new ArrayList<>();
         for(NameValuePair param : mapped.params())
         {
            builder.addParameter(param.getName(), param.getValue());
            usedNames.add(param.getName());
         }
         for(NameValuePair param : spec.getDefaultListParams())
         {
            if(!usedNames.contains(param.getName()))
            {
               builder.addParameter(param.getName(), param.getValue());
            }
         }
         if(AuthentikTables.USER.equals(spec.getName()))
         {
            checkWithinUserScope(mapped.params());
            addUserScope(builder, usedNames);
         }
         builder.addParameter("page", String.valueOf(page));
         builder.addParameter("page_size", String.valueOf(pageSize));
         return (builder.build().toString());
      }
      catch(java.net.URISyntaxException e)
      {
         throw (new QException("Bad Authentik URL", e));
      }
   }



   /*******************************************************************************
    ** Server-side user scope (records are also checked one by one). A filter
    ** the operator set on the same parameter wins server-side; the per-record
    ** check still enforces the scope.
    *******************************************************************************/
   private void checkWithinUserScope(List<NameValuePair> params) throws QUserFacingException
   {
      String       pathPrefix  = runtime().getConfig().getUserScopePathStartsWith();
      List<String> scopeGroups = runtime().getConfig().getUserScopeGroupNames() == null ? List.of() : runtime().getConfig().getUserScopeGroupNames();
      for(NameValuePair param : params)
      {
         boolean outside = switch(param.getName())
         {
            case "type" -> !List.of(AuthentikTables.DEFAULT_USER_TYPES).contains(param.getValue());
            case "path", "path_startswith" -> StringUtils.hasContent(pathPrefix) && !param.getValue().startsWith(pathPrefix);
            case "groups_by_name" -> !scopeGroups.isEmpty() && !scopeGroups.contains(param.getValue());
            default -> false;
         };
         if(outside)
         {
            throw (new QUserFacingException("That filter (" + param.getName() + " = " + param.getValue() + ") is outside the users this app may see."));
         }
      }
   }



   /*******************************************************************************
    ** Scope parameters (the operator's narrower filter, checked above, wins).
    *******************************************************************************/
   private void addUserScope(URIBuilder builder, List<String> usedNames)
   {
      if(!usedNames.contains("type"))
      {
         for(String type : AuthentikTables.DEFAULT_USER_TYPES)
         {
            builder.addParameter("type", type);
         }
      }
      String pathPrefix = runtime().getConfig().getUserScopePathStartsWith();
      if(StringUtils.hasContent(pathPrefix) && !usedNames.contains("path_startswith"))
      {
         builder.addParameter("path_startswith", pathPrefix);
      }
      List<String> groups = runtime().getConfig().getUserScopeGroupNames();
      if(groups != null && !groups.isEmpty() && !usedNames.contains("groups_by_name"))
      {
         groups.forEach(g -> builder.addParameter("groups_by_name", g));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private List<JSONObject> fetchByKeys(QTableMetaData table, AuthentikTableSpec spec, List<Serializable> keys, Integer limit) throws QException
   {
      List<JSONObject> rs = new ArrayList<>();
      for(Serializable key : keys)
      {
         if(key == null)
         {
            continue;
         }
         JSONObject object = getObject(spec, key);
         if(object != null && isVisible(spec, object))
         {
            rs.add(object);
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** Per-record visibility (scope).
    *******************************************************************************/
   private boolean isVisible(AuthentikTableSpec spec, JSONObject object)
   {
      if(AuthentikTables.USER.equals(spec.getName()))
      {
         return (runtime().getGuard().isUserInScope(object));
      }
      return (true);
   }



   /*******************************************************************************
    ** Convert an Authentik object to a QRecord, dropping sensitive fields the
    ** session may not see and computing derived fields.
    *******************************************************************************/
   public QRecord toRecord(AuthentikTableSpec spec, JSONObject object, boolean maySeeSensitive) throws QException
   {
      try
      {
         QRecord record = new QRecord();
         record.setTableName(tableNameOf(spec));
         for(AuthentikFieldSpec field : spec.getFields())
         {
            if(field.isSensitive() && !maySeeSensitive)
            {
               continue;
            }
            record.setValue(field.getName(), field.extract(object));
         }

         if(AuthentikTables.USER.equals(spec.getName()))
         {
            AuthentikGuard.ProtectionResult protection = runtime().getGuard().protection(object);
            record.setValue("isProtected", protection.isProtected());
            if(protection.isProtected())
            {
               record.setDisplayValue("isProtected", "Protected: " + protection.reason());
            }

            EffectivePermissionResolver resolver = resolverForCall();
            if(resolver != null)
            {
               List<String> groupPks = new ArrayList<>();
               JSONArray    groups   = object.optJSONArray("groups_obj");
               for(int i = 0; groups != null && i < groups.length(); i++)
               {
                  groupPks.add(groups.getJSONObject(i).optString("pk"));
               }
               record.setValue("effectivePermissions", String.join(", ", resolver.resolveGroups(groupPks).sessionPermissions()));
            }
            else
            {
               record.setDisplayValue("effectivePermissions", UNAVAILABLE);
            }
         }
         else if(AuthentikTables.GROUP.equals(spec.getName()))
         {
            EffectivePermissionResolver resolver = resolverForCall();
            if(resolver != null)
            {
               String pk = object.optString("pk");
               record.setValue("isSuperuserInherited", resolverGraph.isSuperuserInherited(pk));
               record.setValue("effectivePermissions", String.join(", ", resolver.resolveGroups(List.of(pk)).sessionPermissions()));
            }
            else
            {
               record.setDisplayValue("effectivePermissions", UNAVAILABLE);
               record.setDisplayValue("isSuperuserInherited", UNAVAILABLE);
            }
         }
         else if(AuthentikTables.TOKEN.equals(spec.getName()))
         {
            AuthentikTokenActivity.enrich(this, record);
         }
         return (record);
      }
      catch(JSONException | IllegalArgumentException e)
      {
         throw (new QException("Unexpected Authentik response for " + spec.getLabel() + ": " + e.getMessage(), e));
      }
   }



   /*******************************************************************************
    ** The current group graph: every group with parents, attributes and member
    ** pks (cached for groupCacheTtlSeconds).
    *******************************************************************************/
   public GroupGraph groupGraph() throws QException
   {
      AuthentikRuntime runtime = runtime();
      boolean          cache   = runtime.getConfig().getGroupCacheTtlSeconds() != null && runtime.getConfig().getGroupCacheTtlSeconds() > 0;
      if(cache)
      {
         Optional<GroupGraph> cached = runtime.getGroupGraphCache().getMemoizedResult("all").map(m -> m.getResult());
         if(cached.isPresent())
         {
            return (cached.get());
         }
      }

      List<JSONObject> groups = getAllPages("/core/groups/?include_users=false&include_parents=false&include_children=false&ordering=name", MAX_SWEEP_OBJECTS);
      if(groups.size() >= MAX_SWEEP_OBJECTS)
      {
         throw (new QUserFacingException("More than " + MAX_SWEEP_OBJECTS + " Authentik groups; the group graph is not supported at this size."));
      }
      GroupGraph graph = GroupGraph.fromGroups(groups, runtime.getConfig().getPolicyFormat(), runtime.getPolicyCatalog());
      if(cache)
      {
         runtime.getGroupGraphCache().storeResult("all", graph);
      }
      return (graph);
   }



   /*******************************************************************************
    ** The produced (prefixed) table name for a spec: records must carry it (the
    ** Next UI rejects a record response without a tableName).
    *******************************************************************************/
   private String tableNameOf(AuthentikTableSpec spec)
   {
      return (runtime().getConfig().applyTablePrefix(spec.getName()));
   }



   /*******************************************************************************
    ** The runtime of the backend this util serves (config, guard, caches).
    *******************************************************************************/
   public AuthentikRuntime getRuntime()
   {
      return (runtime());
   }



   /*******************************************************************************
    ** The group graph WITH member pks (one sweep; cached like the plain graph
    ** under a separate key). Used by safety checks that need to know who is in
    ** which group (last-admin protection).
    *******************************************************************************/
   public GroupGraph groupGraphWithMembers() throws QException
   {
      AuthentikRuntime runtime = runtime();
      boolean          cache   = runtime.getConfig().getGroupCacheTtlSeconds() != null && runtime.getConfig().getGroupCacheTtlSeconds() > 0;
      if(cache)
      {
         Optional<GroupGraph> cached = runtime.getGroupGraphCache().getMemoizedResult("members").map(m -> m.getResult());
         if(cached.isPresent())
         {
            return (cached.get());
         }
      }
      List<JSONObject> groups = getAllPages("/core/groups/?include_users=true&include_parents=false&include_children=false&ordering=name", MAX_SWEEP_OBJECTS);
      GroupGraph       graph  = GroupGraph.fromGroups(groups, runtime.getConfig().getPolicyFormat(), runtime.getPolicyCatalog());
      if(cache)
      {
         runtime.getGroupGraphCache().storeResult("members", graph);
      }
      return (graph);
   }



   /*******************************************************************************
    ** Every user the qbit may see (default types, user scope applied), without
    ** group objects. Bounded sweep.
    *******************************************************************************/
   public List<JSONObject> allUsers() throws QException
   {
      try
      {
         URIBuilder builder = new URIBuilder("/core/users/");
         boolean groupScope = runtime().getConfig().getUserScopeGroupNames() != null && !runtime().getConfig().getUserScopeGroupNames().isEmpty();
         builder.addParameter("include_groups", String.valueOf(groupScope));
         builder.addParameter("include_roles", "false");
         addUserScope(builder, List.of());
         List<JSONObject> rs = new ArrayList<>();
         for(JSONObject user : getAllPages(builder.build().toString(), MAX_SWEEP_OBJECTS))
         {
            if(runtime().getGuard().isUserInScope(user))
            {
               rs.add(user);
            }
         }
         return (rs);
      }
      catch(java.net.URISyntaxException e)
      {
         throw (new QException("Bad Authentik URL", e));
      }
   }



   /*******************************************************************************
    ** A bounded, username-ordered policy-preview lookup. Membership, active
    ** status and user scope are evaluated by Authentik before the limit.
    ** This read needs only the editor permission, not the users table permission.
    *******************************************************************************/
   public List<JSONObject> policyPreviewUsers(Collection<String> groupPks, int maxObjects) throws QException
   {
      if(!AuthentikGuard.has(QContext.getQSession(), IdentityPermission.POLICIES_MANAGE))
      {
         throw (new QPermissionDeniedException("You do not have permission to preview policies (authentik.policies.manage)."));
      }
      if(groupPks.isEmpty())
      {
         return (List.of());
      }
      try
      {
         URIBuilder builder = new URIBuilder("/core/users/");
         builder.addParameter("include_groups", "true");
         builder.addParameter("include_roles", "false");
         builder.addParameter("is_active", "true");
         builder.addParameter("ordering", "username");
         for(String pk : groupPks)
         {
            builder.addParameter("groups_by_pk", pk);
         }
         addUserScope(builder, List.of());
         List<JSONObject> users = new ArrayList<>();
         for(JSONObject user : getAllPages(builder.build().toString(), maxObjects))
         {
            if(runtime().getGuard().isUserInScope(user) && user.optBoolean("is_active", false))
            {
               users.add(user);
            }
         }
         return (users);
      }
      catch(java.net.URISyntaxException e)
      {
         throw (new QException("Bad Authentik URL", e));
      }
   }



   /*******************************************************************************
    ** A resolver over the current group graph and the instance's permissions.
    *******************************************************************************/
   public EffectivePermissionResolver resolver() throws QException
   {
      return (new EffectivePermissionResolver(groupGraph(), runtime().getPermissionCatalog()));
   }



   private GroupGraph resolverGraph;
   private boolean    resolverFailed;



   /*******************************************************************************
    ** The resolver for this call (built once per util instance); null when the
    ** group graph cannot be read, in which case derived fields stay empty.
    *******************************************************************************/
   private EffectivePermissionResolver resolverForCall()
   {
      if(resolverForCall == null && !resolverFailed)
      {
         try
         {
            resolverGraph = groupGraph();
            resolverForCall = new EffectivePermissionResolver(resolverGraph, runtime().getPermissionCatalog());
         }
         catch(Exception e)
         {
            resolverFailed = true;
            LOG.warn("Group graph unavailable; effective permissions shown as unavailable", logPair("error", AuthentikRedactor.redactText(String.valueOf(e.getMessage()), token())));
            return (null);
         }
      }
      return (resolverForCall);
   }



   /*******************************************************************************
    ** Rows of the virtual membership table for a filter. Criteria: groupPk
    ** (equals / in), groupName, userPk, username (equals), id (key lookup);
    ** AND only. The narrowest criterion picks the source (a group, a user, or a
    ** sweep of all groups); all criteria are then applied to the rows, which
    ** are sorted by the requested ordering (default group, then username).
    *******************************************************************************/
   public List<JSONObject> memberships(AuthentikTableSpec spec, QQueryFilter filter) throws QException
   {
      AuthentikFilterMapper.MappedFilter mapped = runtime().getFilterMapper().map(spec, filter, runtime().getGuard().maySeeSensitive());

      java.util.Map<String, List<String>> wanted   = new java.util.LinkedHashMap<>();
      String                              ordering = "groupName";
      for(NameValuePair param : mapped.params())
      {
         if(param.getName().equals("ordering"))
         {
            ordering = param.getValue();
         }
         else
         {
            wanted.computeIfAbsent(param.getName(), k -> new ArrayList<>()).add(param.getValue());
         }
      }
      if(mapped.isKeyLookup())
      {
         for(Serializable key : mapped.keyLookup())
         {
            String[] parts = String.valueOf(key).split(":", 2);
            if(parts.length == 2)
            {
               wanted.computeIfAbsent("groupPk", k -> new ArrayList<>()).add(parts[0]);
               wanted.computeIfAbsent("id", k -> new ArrayList<>()).add(String.valueOf(key));
            }
         }
         if(!wanted.containsKey("id"))
         {
            return (List.of());
         }
      }

      List<JSONObject> rows = new ArrayList<>();
      if(wanted.containsKey("groupPk"))
      {
         for(String groupPk : new java.util.LinkedHashSet<>(wanted.get("groupPk")))
         {
            JSONObject group = groupPk.matches("[A-Za-z0-9-]+") ? getJsonOrNull(runtime().getConfig().getApiRoot() + "/core/groups/" + groupPk + "/?include_users=true") : null;
            addGroupRows(rows, group);
         }
      }
      else if(wanted.containsKey("groupName"))
      {
         JSONArray results = getApiJson("/core/groups/?include_users=true&name=" + encode(wanted.get("groupName").get(0))).optJSONArray("results");
         addGroupRows(rows, results == null || results.isEmpty() ? null : results.getJSONObject(0));
      }
      else if(wanted.containsKey("userPk") || wanted.containsKey("username"))
      {
         JSONObject user;
         if(wanted.containsKey("userPk"))
         {
            String userPk = wanted.get("userPk").get(0);
            user = userPk.matches("[0-9]+") ? getJsonOrNull(runtime().getConfig().getApiRoot() + "/core/users/" + userPk + "/") : null;
         }
         else
         {
            JSONArray results = getApiJson("/core/users/?include_groups=true&username=" + encode(wanted.get("username").get(0))).optJSONArray("results");
            user = results == null || results.isEmpty() ? null : results.getJSONObject(0);
         }
         addUserRows(rows, user);
      }
      else
      {
         List<JSONObject> groups = getAllPages("/core/groups/?include_users=true&ordering=name", MAX_SWEEP_OBJECTS);
         for(JSONObject group : groups)
         {
            addGroupRows(rows, group);
         }
         if(rows.size() >= MAX_SWEEP_OBJECTS || groups.size() >= MAX_SWEEP_OBJECTS)
         {
            throw (new QUserFacingException("Too many memberships to list without a filter; filter by group or user."));
         }
      }

      List<JSONObject> matching = new ArrayList<>();
      for(JSONObject row : rows)
      {
         boolean keep = true;
         for(java.util.Map.Entry<String, List<String>> entry : wanted.entrySet())
         {
            if(!entry.getValue().contains(String.valueOf(row.opt(entry.getKey()))))
            {
               keep = false;
               break;
            }
         }
         if(keep && isMemberInScope(row))
         {
            matching.add(row);
         }
      }

      matching.sort(membershipComparator(ordering));
      return (matching);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static java.util.Comparator<JSONObject> membershipComparator(String ordering)
   {
      java.util.Comparator<JSONObject> rs = null;
      for(String part : ordering.split(","))
      {
         boolean                          descending = part.startsWith("-");
         String                           field      = descending ? part.substring(1) : part;
         java.util.Comparator<JSONObject> one        = java.util.Comparator.comparing(o -> o.optString(field, ""), String.CASE_INSENSITIVE_ORDER);
         if(descending)
         {
            one = one.reversed();
         }
         rs = rs == null ? one : rs.thenComparing(one);
      }
      java.util.Comparator<JSONObject> tieBreak = java.util.Comparator.comparing(o -> o.optString("groupName", "") + "\u0000" + o.optString("username", ""));
      return (rs == null ? tieBreak : rs.thenComparing(tieBreak));
   }



   /*******************************************************************************
    ** Rows for every member of a group (from users_obj).
    *******************************************************************************/
   private static void addGroupRows(List<JSONObject> rows, JSONObject group)
   {
      if(group == null)
      {
         return;
      }
      JSONArray users = group.optJSONArray("users_obj");
      for(int i = 0; users != null && i < users.length(); i++)
      {
         JSONObject user = users.getJSONObject(i);
         rows.add(membershipRow(group.optString("pk"), group.optString("name"), user));
      }
   }



   /*******************************************************************************
    ** Rows for every group of a user (from groups_obj).
    *******************************************************************************/
   private static void addUserRows(List<JSONObject> rows, JSONObject user)
   {
      if(user == null)
      {
         return;
      }
      JSONArray groups = user.optJSONArray("groups_obj");
      for(int i = 0; groups != null && i < groups.length(); i++)
      {
         JSONObject group = groups.getJSONObject(i);
         rows.add(membershipRow(group.optString("pk"), group.optString("name"), user));
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static JSONObject membershipRow(String groupPk, String groupName, JSONObject user)
   {
      return (new JSONObject()
         .put("id", groupPk + ":" + user.optInt("pk"))
         .put("groupPk", groupPk)
         .put("groupName", groupName)
         .put("userPk", user.optInt("pk"))
         .put("username", user.optString("username"))
         .put("name", user.optString("name"))
         .put("email", user.optString("email"))
         .put("isActive", user.optBoolean("is_active", true)));
   }



   /*******************************************************************************
    ** Membership rows carry partial users (no type or path), so with a user
    ** scope configured each member is checked through a (cached) user GET.
    *******************************************************************************/
   private boolean isMemberInScope(JSONObject row) throws QException
   {
      if(scopedUserPks == null)
      {
         scopedUserPks = new java.util.HashSet<>();
         try
         {
            URIBuilder builder = new URIBuilder("/core/users/");
            addUserScope(builder, List.of());
            String query = builder.build().getRawQuery();
            for(JSONObject user : getAllPages("/core/users/?" + query, MAX_SWEEP_OBJECTS))
            {
               if(runtime().getGuard().isUserInScope(user))
               {
                  scopedUserPks.add(user.getInt("pk"));
               }
            }
         }
         catch(java.net.URISyntaxException e)
         {
            throw (new QException("Bad Authentik URL", e));
         }
      }
      return (scopedUserPks.contains(row.optInt("userPk")));
   }



   private java.util.Set<Integer> scopedUserPks;



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String encode(String value)
   {
      return (java.net.URLEncoder.encode(value, StandardCharsets.UTF_8));
   }



   /*******************************************************************************
    ** GET JSON through the response cache.
    *******************************************************************************/
   private JSONObject getJson(String url) throws QException
   {
      String body = getBody(url, false);
      return (parse(url, body));
   }



   /*******************************************************************************
    ** The pagination object of a list response; a list response without one
    ** means the API changed, which must not read as "no results".
    *******************************************************************************/
   static JSONObject pagination(JSONObject response) throws QException
   {
      JSONObject pagination = response.optJSONObject("pagination");
      if(pagination == null)
      {
         throw (new QException("Unexpected Authentik list response (no pagination object); has the API changed?"));
      }
      return (pagination);
   }



   /*******************************************************************************
    ** GET an API path (relative to /api/v3) as JSON, or null on 404.
    *******************************************************************************/
   public JSONObject getApiJsonOrNull(String pathAndQuery) throws QException
   {
      return (getJsonOrNull(runtime().getConfig().getApiRoot() + pathAndQuery));
   }



   /*******************************************************************************
    ** GET JSON, or null on 404.
    *******************************************************************************/
   private JSONObject getJsonOrNull(String url) throws QException
   {
      String body = getBody(url, true);
      return (body == null ? null : parse(url, body));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private String getBody(String url, boolean nullOn404) throws QException
   {
      AuthentikRuntime runtime = runtime();
      if(runtime.isCacheEnabled())
      {
         Optional<String> cached = runtime.getResponseCache().getMemoizedResult(url).map(m -> m.getResult());
         if(cached.isPresent())
         {
            return (cached.get());
         }
      }

      QHttpResponse response = execute(new HttpGet(url));
      if(response.getStatusCode() == 404 && nullOn404)
      {
         return (null);
      }
      if(response.getStatusCode() == 404)
      {
         throw (new QException("Authentik endpoint not found (404): " + pathOf(url)));
      }

      String body = response.getContent();
      if(runtime.isCacheEnabled() && body != null)
      {
         runtime.getResponseCache().storeResult(url, body);
      }
      return (body);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private JSONObject parse(String url, String body) throws QException
   {
      try
      {
         return (new JSONObject(body));
      }
      catch(JSONException e)
      {
         throw (new QException("Authentik returned a non-JSON response for " + pathOf(url)));
      }
   }



   /*******************************************************************************
    ** Execute a request: throttle, auth, retries for 429 and (GET-only) 5xx,
    ** error mapping, logging. Returns 2xx and 404 responses.
    *******************************************************************************/
   public QHttpResponse execute(HttpRequestBase request) throws QException
   {
      return (execute(request, token(), false));
   }



   /*******************************************************************************
    ** Shared request loop; exchange responses and all token traffic stay secret.
    *******************************************************************************/
   private QHttpResponse execute(HttpRequestBase request, String token, boolean exchange) throws QException
   {
      String path       = pathOf(request.getURI().toString());
      int    attempts   = 0;
      int    backoffMs  = INITIAL_BACKOFF_MS;

      if(!exchange && !StringUtils.hasContent(token))
      {
         throw (new QException("The Authentik API token is not configured (apiToken resolved to an empty value)."));
      }

      while(true)
      {
         attempts++;
         runtime().getThrottle().acquire();
         if(!exchange)
         {
            request.setHeader("Authorization", "Bearer " + token);
         }
         request.setHeader("Accept", "application/json");
         if(request instanceof HttpEntityEnclosingRequest)
         {
            request.setHeader("Content-Type", exchange ? "application/x-www-form-urlencoded" : "application/json");
         }

         long          start = System.currentTimeMillis();
         QHttpResponse response;
         try
         {
            response = send(request);
         }
         catch(Exception e)
         {
            String message = exchange || AuthentikRedactor.isSensitivePath(path) ? "Sensitive request failed" : AuthentikRedactor.redactText(e.getMessage(), token);
            LOG.warn("Authentik API call failed", logPair("method", request.getMethod()), logPair("path", path), logPair("error", message));
            if(attempts < MAX_RETRIES && "GET".equals(request.getMethod()))
            {
               SleepUtils.sleep(backoffMs, java.util.concurrent.TimeUnit.MILLISECONDS);
               backoffMs *= 2;
               continue;
            }
            throw (new QException("Could not reach Authentik (" + request.getMethod() + " " + path + "): " + message));
         }

         int status = response.getStatusCode() == null ? 0 : response.getStatusCode();
         LOG.info("Authentik API call", logPair("method", request.getMethod()), logPair("path", path), logPair("status", status), logPair("millis", System.currentTimeMillis() - start));
         if(!exchange)
         {
            logOutboundCall(request, path, response, token);
         }
         checkVersionOnce(status);

         if(status == 429 && attempts <= MAX_RETRIES)
         {
            SleepUtils.sleep(retryAfterMillis(response, backoffMs), java.util.concurrent.TimeUnit.MILLISECONDS);
            backoffMs *= 2;
            continue;
         }
         if(status >= 500 && attempts < MAX_RETRIES && "GET".equals(request.getMethod()))
         {
            SleepUtils.sleep(backoffMs, java.util.concurrent.TimeUnit.MILLISECONDS);
            backoffMs *= 2;
            continue;
         }

         if((status >= 200 && status < 300) || status == 404)
         {
            return (response);
         }
         if(exchange)
         {
            String error = "exchange_failed";
            try
            {
               String code = new JSONObject(response.getContent()).optString("error");
               if(List.of("invalid_grant", "access_denied", "invalid_client", "invalid_request", "unsupported_grant_type", "invalid_scope").contains(code))
               {
                  error = code;
               }
            }
            catch(JSONException ignored)
            {
               // Never echo an untrusted broker error body.
            }
            throw (new QUserFacingException("Authentik refused to act as you (" + error + ")"));
         }
         throw (mapError(request, path, status, response.getContent(), token));
      }
   }



   /*******************************************************************************
    ** Send one request. The single seam tests override.
    *******************************************************************************/
   protected QHttpResponse send(HttpRequestBase request) throws Exception
   {
      try(CloseableHttpClient client = buildHttpClient(); CloseableHttpResponse response = executeHttpRequest(request, client))
      {
         QHttpResponse qResponse = new QHttpResponse();
         qResponse.setStatusCode(response.getStatusLine().getStatusCode());
         qResponse.setHeaderList(List.of(response.getAllHeaders()));
         qResponse.setContent(response.getEntity() == null ? null : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
         return (qResponse);
      }
   }



   /*******************************************************************************
    ** HTTP client with the configured timeouts.
    *******************************************************************************/
   @Override
   protected CloseableHttpClient buildHttpClient()
   {
      return (HttpClientBuilder.create()
         .disableRedirectHandling()
         .setDefaultRequestConfig(RequestConfig.custom()
            .setConnectTimeout(runtime().getConfig().getConnectTimeoutMillis())
            .setConnectionRequestTimeout(runtime().getConfig().getConnectTimeoutMillis())
            .setSocketTimeout(runtime().getConfig().getSocketTimeoutMillis()).build())
         .build());
   }



   /*******************************************************************************
    ** Map an Authentik error response to an exception, with a redacted message.
    *******************************************************************************/
   static QException mapError(HttpRequestBase request, String path, int status, String body, String token)
   {
      String detail = AuthentikRedactor.redactText(errorDetail(AuthentikRedactor.redactText(body, token)), token);
      if(AuthentikRedactor.isSensitivePath(path))
      {
         detail = "(details omitted for a sensitive endpoint)";
      }
      return switch(status)
      {
         case 400 -> new QUserFacingException("Authentik rejected the request: " + detail);
         case 401 -> new QException("Authentik rejected the qbit's API token (401). The service-account token may be expired or revoked; rotate it (see the phase 0 owner checklist).");
         case 403 -> new QPermissionDeniedException("Authentik refused " + request.getMethod() + " " + path + " (403): " + detail);
         default -> new QException("Authentik error " + status + " on " + request.getMethod() + " " + path + ": " + detail);
      };
   }



   /*******************************************************************************
    ** Flatten Authentik's error JSON ({"detail": ...} or {"field": ["msg"]}).
    *******************************************************************************/
   static String errorDetail(String body)
   {
      if(body == null || body.isBlank())
      {
         return ("(no details)");
      }
      try
      {
         JSONObject       object = new JSONObject(body);
         List<String>     parts  = new ArrayList<>();
         Iterator<String> keys   = object.keys();
         while(keys.hasNext())
         {
            String key   = keys.next();
            Object value = object.get(key);
            String text  = value instanceof JSONArray array ? joinArray(array) : String.valueOf(value);
            parts.add(key.equals("detail") || key.equals("non_field_errors") ? text : key + ": " + text);
         }
         return (String.join("; ", parts));
      }
      catch(JSONException e)
      {
         return (body.length() > 200 ? body.substring(0, 200) + "..." : body);
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String joinArray(JSONArray array)
   {
      List<String> values = new ArrayList<>();
      for(int i = 0; i < array.length(); i++)
      {
         values.add(String.valueOf(array.get(i)));
      }
      return (String.join(" ", values));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static long retryAfterMillis(QHttpResponse response, int fallbackMillis)
   {
      for(Header header : response.getHeaderList() == null ? List.<Header>of() : response.getHeaderList())
      {
         if(header.getName().equalsIgnoreCase("Retry-After"))
         {
            try
            {
               return (Math.min(MAX_RETRY_AFTER_SECS, Long.parseLong(header.getValue().trim())) * 1000L);
            }
            catch(NumberFormatException e)
            {
               break;
            }
         }
      }
      return (fallbackMillis);
   }



   /*******************************************************************************
    ** Write an OutboundAPILog row (if the host has that table), keeping PII
    ** out: no query string, no successful GET bodies, sensitive bodies
    ** dropped, everything else redacted.
    *******************************************************************************/
   protected void logOutboundCall(HttpRequestBase request, String path, QHttpResponse response, String token)
   {
      try
      {
         if(QContext.getQInstance() == null || QContext.getQInstance().getTable(OutboundAPILog.TABLE_NAME) == null)
         {
            return;
         }

         String requestBody = null;
         if("POST".equals(request.getMethod()) && path.endsWith("/core/users/"))
         {
            path = path + " [body omitted: user create]";
         }
         else if(request instanceof HttpEntityEnclosingRequest entityRequest && entityRequest.getEntity() != null)
         {
            requestBody = EntityUtils.toString(entityRequest.getEntity(), StandardCharsets.UTF_8);
         }

         int    status       = response.getStatusCode() == null ? 0 : response.getStatusCode();
         String responseBody = "GET".equals(request.getMethod()) && status < 400
            ? "[" + (response.getContent() == null ? 0 : response.getContent().length()) + " characters, not stored]"
            : AuthentikRedactor.redactBody(path, response.getContent(), token);

         OutboundAPILog log = new OutboundAPILog()
            .withMethod(request.getMethod())
            .withUrl(path)
            .withTimestamp(Instant.now())
            .withRequestBody(AuthentikRedactor.redactBody(path, requestBody, token))
            .withStatusCode(status)
            .withResponseBody(responseBody);

         InsertInput insertInput = new InsertInput();
         insertInput.setTableName(OutboundAPILog.TABLE_NAME);
         insertInput.setRecords(List.of(log.toQRecord()));
         new InsertAction().executeAsync(insertInput);
      }
      catch(Exception e)
      {
         LOG.warn("Error logging an outbound Authentik call", logPair("path", path), logPair("error", e.getClass().getSimpleName()));
      }
   }



   /*******************************************************************************
    ** Once per JVM, after the first successful call, compare the server's
    ** major.minor to the configured expectation and warn on a mismatch.
    *******************************************************************************/
   private void checkVersionOnce(int status)
   {
      if(status < 200 || status >= 300 || !VERSION_CHECKED.compareAndSet(false, true))
      {
         return;
      }
      String expected = runtime().getConfig().getExpectedServerVersion();
      Optional<String> version = fetchServerVersion();
      if(version.isEmpty())
      {
         VERSION_CHECKED.set(false);
         return;
      }
      version.ifPresent(actual ->
      {
         if(StringUtils.hasContent(expected) && !actual.startsWith(expected + ".") && !actual.equals(expected))
         {
            LOG.warn("Authentik server version differs from the version qbit-authentik was tested against", logPair("expected", expected), logPair("actual", actual));
         }
      });
   }



   /*******************************************************************************
    ** Reset the once-per-JVM version check (tests).
    *******************************************************************************/
   static void resetVersionCheck()
   {
      VERSION_CHECKED.set(false);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private String token()
   {
      return (runtime().getConfig().getResolvedApiToken());
   }



   /*******************************************************************************
    ** The path of a URL without its query string (query strings may carry PII).
    *******************************************************************************/
   static String pathOf(String url)
   {
      try
      {
         return (URI.create(url).getPath());
      }
      catch(IllegalArgumentException e)
      {
         int q = url.indexOf('?');
         return (q < 0 ? url : url.substring(0, q));
      }
   }

}
