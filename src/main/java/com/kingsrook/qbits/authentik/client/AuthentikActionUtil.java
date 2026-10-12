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
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.security.AuthentikGuard;
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
import org.apache.http.Header;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
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

      AuthentikFilterMapper.MappedFilter mapped = map(spec, countInput.getFilter());
      CountOutput                        output = new CountOutput();
      if(mapped.isKeyLookup())
      {
         output.setCount(fetchByKeys(table, spec, mapped.keyLookup(), null).size());
         return (output);
      }

      JSONObject page = getJson(listUrl(spec, mapped, 1, 1));
      output.setCount(page.optJSONObject("pagination") == null ? 0 : page.getJSONObject("pagination").optInt("count", 0));
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

      QueryOutput                        output    = new QueryOutput(queryInput);
      QQueryFilter                       filter    = queryInput.getFilter();
      AuthentikFilterMapper.MappedFilter mapped    = map(spec, filter);
      boolean                            sensitive = runtime().getGuard().maySeeSensitive();

      Integer limit = filter == null ? null : filter.getLimit();
      int     skip  = filter == null || filter.getSkip() == null ? 0 : filter.getSkip();

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

         JSONObject pagination = response.optJSONObject("pagination");
         int        totalPages = pagination == null ? page : pagination.optInt("total_pages", page);
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
    ** Fetch a single Authentik object by key (null when it doesn't exist).
    ** No permission check: callers check first.
    *******************************************************************************/
   public JSONObject getObject(AuthentikTableSpec spec, Serializable key) throws QException
   {
      String keyText = String.valueOf(key).trim();
      if(keyText.isEmpty() || !keyText.matches("[A-Za-z0-9._:-]+"))
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
         JSONObject pagination = response.optJSONObject("pagination");
         if(rs.size() >= maxObjects || pagination == null || page >= pagination.optInt("total_pages", page))
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
         }
         return (record);
      }
      catch(JSONException | IllegalArgumentException e)
      {
         throw (new QException("Unexpected Authentik response for " + spec.getLabel() + ": " + e.getMessage(), e));
      }
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
      String path       = pathOf(request.getURI().toString());
      int    attempts   = 0;
      int    backoffMs  = INITIAL_BACKOFF_MS;
      String token      = token();

      if(!StringUtils.hasContent(token))
      {
         throw (new QException("The Authentik API token is not configured (apiToken resolved to an empty value)."));
      }

      while(true)
      {
         attempts++;
         runtime().getThrottle().acquire();
         request.setHeader("Authorization", "Bearer " + token);
         request.setHeader("Accept", "application/json");
         if(request instanceof HttpEntityEnclosingRequest)
         {
            request.setHeader("Content-Type", "application/json");
         }

         long          start = System.currentTimeMillis();
         QHttpResponse response;
         try
         {
            response = send(request);
         }
         catch(Exception e)
         {
            String message = AuthentikRedactor.redactText(e.getMessage(), token);
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
         logOutboundCall(request, path, response, token);
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
      String detail = AuthentikRedactor.redactText(errorDetail(body), token);
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
         if(request instanceof HttpEntityEnclosingRequest entityRequest && entityRequest.getEntity() != null)
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
         LOG.warn("Error logging an outbound Authentik call", logPair("path", path));
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
      fetchServerVersion().ifPresent(actual ->
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
