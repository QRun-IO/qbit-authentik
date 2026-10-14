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

package com.kingsrook.qbits.authentik.contract;


import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.json.JSONObject;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;


/*******************************************************************************
 ** Disposable Authentik for contract tests (DESIGN.md section 10): Authentik
 ** server + worker (2026.8.3 unless -Dauthentik.test.image), Postgres, and
 ** Mailpit, on a private network. Started once per JVM and shared by every
 ** contract test class.
 **
 ** The two kof22-shaped blueprints from src/test/resources/blueprints are in
 ** /blueprints/custom BEFORE the first boot, so the stack starts as an EMPTY
 ** instance applying the bootstrap: that is contract test (h).
 **
 ** Credentials here are test-only constants for a throwaway container: the
 ** bootstrap admin token (AUTHENTIK_BOOTSTRAP_TOKEN), and a service-account
 ** token minted through the admin API at start-up.
 *******************************************************************************/
public final class AuthentikTestStack
{
   public static final String BOOTSTRAP_TOKEN    = "contract-test-bootstrap-token-0123456789";
   public static final String BOOTSTRAP_PASSWORD = "contract-test-password-123";
   public static final String SERVICE_ACCOUNT    = "qqq-kof22-admin-idadmin";
   public static final String BREAK_GLASS        = "kof22-breakglass";
   public static final String SUPERUSER_GROUP    = "authentik Admins";
   public static final String INFRA_BLUEPRINT    = "kof22-oauth2-apps";
   public static final String BOOTSTRAP_BLUEPRINT = "kof22-identity-bootstrap";
   public static final String APP_SLUG           = "kof22-website-prod";

   public static final String TOKEN_BROKER_CLIENT_SECRET = "contract-test-token-broker-secret";
   public static final String TOKEN_BLUEPRINT = "kof22-qqq-tokens";
   private static final String SECRET_KEY        = "contract-test-secret-key-0123456789abcdefghijklmnop";
   public static final String SA_TOKEN_ID       = "qqq-contract-test";

   private static AuthentikTestStack instance;

   private final Network                         network = Network.newNetwork();
   private final PostgreSQLContainer<?>          postgres;
   private final GenericContainer<?>             mailpit;
   private final GenericContainer<?>             server;
   private final GenericContainer<?>             worker;
   private String                                serviceAccountToken;



   /*******************************************************************************
    ** The shared, started stack.
    *******************************************************************************/
   public static synchronized AuthentikTestStack get()
   {
      if(instance == null)
      {
         AuthentikTestStack stack = new AuthentikTestStack();
         stack.start();
         instance = stack;
         Runtime.getRuntime().addShutdownHook(new Thread(stack::stop));
      }
      return (instance);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @SuppressWarnings("resource")
   private AuthentikTestStack()
   {
      String authentikImage = System.getProperty("authentik.test.image", "ghcr.io/goauthentik/server:2026.8.3");
      String postgresImage  = System.getProperty("postgres.test.image", "postgres:16-alpine");
      String mailpitImage   = System.getProperty("mailpit.test.image", "axllent/mailpit:v1.27");

      postgres = new PostgreSQLContainer<>(DockerImageName.parse(postgresImage).asCompatibleSubstituteFor("postgres"))
         .withNetwork(network)
         .withNetworkAliases("postgresql")
         .withDatabaseName("authentik")
         .withUsername("authentik")
         .withPassword("authentik-test");

      mailpit = new GenericContainer<>(DockerImageName.parse(mailpitImage))
         .withNetwork(network)
         .withNetworkAliases("mailpit")
         .withExposedPorts(8025)
         .waitingFor(Wait.forHttp("/api/v1/info").forPort(8025));

      Map<String, String> env = new HashMap<>();
      env.put("AUTHENTIK_SECRET_KEY", SECRET_KEY);
      env.put("AUTHENTIK_POSTGRESQL__HOST", "postgresql");
      env.put("AUTHENTIK_POSTGRESQL__USER", "authentik");
      env.put("AUTHENTIK_POSTGRESQL__PASSWORD", "authentik-test");
      env.put("AUTHENTIK_POSTGRESQL__NAME", "authentik");
      env.put("AUTHENTIK_BOOTSTRAP_TOKEN", BOOTSTRAP_TOKEN);
      env.put("AUTHENTIK_BOOTSTRAP_PASSWORD", BOOTSTRAP_PASSWORD);
      env.put("AUTHENTIK_BOOTSTRAP_EMAIL", "akadmin@example.test");
      env.put("AUTHENTIK_EMAIL__HOST", "mailpit");
      env.put("AUTHENTIK_EMAIL__PORT", "1025");
      env.put("AUTHENTIK_EMAIL__FROM", "authentik@example.test");
      env.put("AUTHENTIK_ERROR_REPORTING__ENABLED", "false");
      env.put("AUTHENTIK_DISABLE_UPDATE_CHECK", "true");
      env.put("AUTHENTIK_DISABLE_STARTUP_ANALYTICS", "true");
      env.put("KOF22_OAUTH2_CLIENT_SECRET", "contract-test-oauth2-client-secret");
      env.put("KOF22_TOKEN_BROKER_CLIENT_SECRET", TOKEN_BROKER_CLIENT_SECRET);

      server = authentik(authentikImage, env, "server")
         .withNetworkAliases("authentik")
         .withExposedPorts(9000)
         .waitingFor(Wait.forHttp("/-/health/ready/").forPort(9000).forStatusCode(200).withStartupTimeout(Duration.ofMinutes(8)));

      worker = authentik(authentikImage, env, "worker");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @SuppressWarnings("resource")
   private GenericContainer<?> authentik(String image, Map<String, String> env, String command)
   {
      return (new GenericContainer<>(DockerImageName.parse(image))
         .withNetwork(network)
         .withEnv(env)
         .withCommand(command)
         .withCopyFileToContainer(MountableFile.forClasspathResource("blueprints/" + INFRA_BLUEPRINT + ".yaml"), "/blueprints/custom/" + INFRA_BLUEPRINT + ".yaml")
         .withCopyFileToContainer(MountableFile.forClasspathResource("blueprints/" + TOKEN_BLUEPRINT + ".yaml"), "/blueprints/custom/" + TOKEN_BLUEPRINT + ".yaml")
         .withCopyFileToContainer(MountableFile.forClasspathResource("blueprints/" + BOOTSTRAP_BLUEPRINT + ".yaml"), "/blueprints/custom/" + BOOTSTRAP_BLUEPRINT + ".yaml"));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void start()
   {
      postgres.start();
      mailpit.start();
      worker.start();
      server.start();

      TestApi admin = admin();
      try
      {
         waitFor(Duration.ofMinutes(8), "all three kof22 blueprints applied", () ->
            isSuccessful(admin, INFRA_BLUEPRINT) && isSuccessful(admin, BOOTSTRAP_BLUEPRINT) && isSuccessful(admin, TOKEN_BLUEPRINT)
               && admin.first("/core/users/?username=" + SERVICE_ACCOUNT) != null);
      }
      catch(IllegalStateException e)
      {
         ////////////////////////////////////////////////////////////////
         // say which blueprint failed and why (the worker logs it)    //
         ////////////////////////////////////////////////////////////////
         for(String name : List.of(INFRA_BLUEPRINT, BOOTSTRAP_BLUEPRINT, TOKEN_BLUEPRINT))
         {
            JSONObject instance = blueprint(name);
            System.err.println("blueprint " + name + ": " + (instance == null ? "missing" : instance.optString("status")));
         }
         worker.getLogs().lines().filter(line -> line.contains("blueprint") && (line.contains("error") || line.contains("warning") || line.contains("fail")))
            .limit(60).forEach(line -> System.err.println("worker: " + line));
         throw (e);
      }

      int              serviceAccountPk = admin.userPk(SERVICE_ACCOUNT);
      TestApi.Response created          = admin.post("/core/tokens/", new JSONObject().put("identifier", SA_TOKEN_ID).put("user", serviceAccountPk).put("intent", "api").put("expiring", false));
      if(created.status() != 201)
      {
         throw (new IllegalStateException("Could not create the service-account test token: " + created.status() + " " + created.body()));
      }
      serviceAccountToken = admin.getOk("/core/tokens/" + SA_TOKEN_ID + "/view_key/").getString("key");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void stop()
   {
      for(GenericContainer<?> container : new GenericContainer<?>[] { server, worker, mailpit, postgres })
      {
         try
         {
            container.stop();
         }
         catch(Exception e)
         {
            // best effort at JVM exit
         }
      }
      network.close();
   }



   /*******************************************************************************
    ** Run a command in the Authentik server container (for example `ak shell
    ** -c ...`), for setup the API cannot do (creating MFA devices). Returns stdout;
    ** throws when the command fails.
    *******************************************************************************/
   public String execInServer(String... command)
   {
      try
      {
         org.testcontainers.containers.Container.ExecResult result = server.execInContainer(command);
         if(result.getExitCode() != 0)
         {
            throw (new IllegalStateException("Command failed (" + result.getExitCode() + "): " + result.getStderr()));
         }
         return (result.getStdout());
      }
      catch(java.io.IOException | InterruptedException e)
      {
         throw (new IllegalStateException(e));
      }
   }



   /*******************************************************************************
    ** Host root, e.g. http://localhost:32768 (the qbit's baseUrl).
    *******************************************************************************/
   public String baseUrl()
   {
      return ("http://" + server.getHost() + ":" + server.getMappedPort(9000));
   }



   /*******************************************************************************
    ** API root, baseUrl + /api/v3.
    *******************************************************************************/
   public String apiRoot()
   {
      return (baseUrl() + "/api/v3");
   }



   /*******************************************************************************
    ** Mailpit API root.
    *******************************************************************************/
   public String mailpitRoot()
   {
      return ("http://" + mailpit.getHost() + ":" + mailpit.getMappedPort(8025));
   }



   /*******************************************************************************
    ** Client acting as the bootstrap superuser (akadmin), for setup.
    *******************************************************************************/
   public TestApi admin()
   {
      return (new TestApi(apiRoot(), BOOTSTRAP_TOKEN));
   }



   /*******************************************************************************
    ** Client acting as the qbit's service account.
    *******************************************************************************/
   public TestApi serviceAccount()
   {
      return (new TestApi(apiRoot(), serviceAccountToken));
   }



   /*******************************************************************************
    ** The service account's token (for configuring the qbit under test).
    *******************************************************************************/
   public String serviceAccountToken()
   {
      return (serviceAccountToken);
   }



   /*******************************************************************************
    ** Grant only permissions absent from the production fixture. Callers remove
    ** exactly the returned list, preserving shared baseline role permissions.
    *******************************************************************************/
   public java.util.List<String> grantTemporaryPermissions(java.util.List<String> requested)
   {
      java.util.Set<String> baseline = new java.util.HashSet<>();
      try(java.io.InputStream input = AuthentikTestStack.class.getResourceAsStream("/blueprints/" + BOOTSTRAP_BLUEPRINT + ".yaml"))
      {
         String yaml = new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
         java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("(?m)^        - (authentik_[a-z_]+\\.[a-z_]+)\\s*$").matcher(yaml);
         while(matcher.find())
         {
            baseline.add(matcher.group(1));
         }
      }
      catch(java.io.IOException e)
      {
         throw (new IllegalStateException("Cannot read baseline role permissions", e));
      }
      java.util.List<String> additional = requested.stream().filter(permission -> !baseline.contains(permission)).toList();
      if(!additional.isEmpty())
      {
         String role = admin().first("/rbac/roles/?name=" + SERVICE_ACCOUNT).getString("pk");
         TestApi.Response response = admin().post("/rbac/permissions/assigned_by_roles/" + role + "/assign/",
            new JSONObject().put("permissions", new org.json.JSONArray(additional)));
         if(response.status() != 200)
         {
            throw (new IllegalStateException("Temporary permission grant failed: HTTP " + response.status()));
         }
      }
      return (additional);
   }



   /*******************************************************************************
    ** Remove only the temporary grants, including on assertion failure.
    *******************************************************************************/
   public void removeTemporaryPermissions(java.util.List<String> additional)
   {
      if(!additional.isEmpty())
      {
         String role = admin().first("/rbac/roles/?name=" + SERVICE_ACCOUNT).getString("pk");
         TestApi.Response response = admin().patch("/rbac/permissions/assigned_by_roles/" + role + "/unassign/",
            new JSONObject().put("permissions", new org.json.JSONArray(additional)));
         if(response.status() != 204)
         {
            throw (new IllegalStateException("Temporary permission cleanup failed: HTTP " + response.status()));
         }
      }
   }



   /*******************************************************************************
    ** The blueprint instance with this name.
    *******************************************************************************/
   public JSONObject blueprint(String name)
   {
      return (admin().first("/managed/blueprints/?name=" + TestApi.encode(name)));
   }



   /*******************************************************************************
    ** Re-apply a blueprint instance (POST .../apply/, which is asynchronous) and
    ** wait until it has applied again successfully.
    *******************************************************************************/
   public void applyAndWait(String name)
   {
      JSONObject before      = blueprint(name);
      String     lastApplied = before.optString("last_applied", "");
      admin().post("/managed/blueprints/" + before.getString("pk") + "/apply/", new JSONObject());
      waitFor(Duration.ofMinutes(3), "blueprint " + name + " re-applied", () ->
      {
         JSONObject now = blueprint(name);
         return (!now.optString("last_applied", "").equals(lastApplied) && "successful".equals(now.optString("status")));
      });
   }



   /*******************************************************************************
    ** Create a content-based blueprint instance and wait for it to apply.
    *******************************************************************************/
   public JSONObject createContentBlueprint(String name, String yaml)
   {
      TestApi.Response created = admin().post("/managed/blueprints/", new JSONObject().put("name", name).put("content", yaml).put("enabled", true).put("path", ""));
      if(created.status() != 201)
      {
         throw (new IllegalStateException("Could not create blueprint " + name + ": " + created.status() + " " + created.body()));
      }
      applyAndWait(name);
      return (blueprint(name));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static boolean isSuccessful(TestApi admin, String name)
   {
      try
      {
         JSONObject blueprint = admin.first("/managed/blueprints/?name=" + TestApi.encode(name));
         return (blueprint != null && "successful".equals(blueprint.optString("status")));
      }
      catch(Exception e)
      {
         return (false);
      }
   }



   /*******************************************************************************
    ** Poll until a condition holds.
    *******************************************************************************/
   public static void waitFor(Duration timeout, String what, BooleanSupplier condition)
   {
      Instant deadline = Instant.now().plus(timeout);
      while(Instant.now().isBefore(deadline))
      {
         if(condition.getAsBoolean())
         {
            return;
         }
         try
         {
            Thread.sleep(2_000);
         }
         catch(InterruptedException e)
         {
            Thread.currentThread().interrupt();
            break;
         }
      }
      throw (new IllegalStateException("Timed out waiting for " + what));
   }

}
