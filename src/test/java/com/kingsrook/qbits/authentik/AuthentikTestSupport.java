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


import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QUser;
import com.kingsrook.qqq.backend.module.api.model.metadata.APIBackendMetaData;


/*******************************************************************************
 ** Shared test helpers: build a QInstance with the qbit, swap in a test action
 ** util, and log in with chosen identity permissions.
 *******************************************************************************/
public final class AuthentikTestSupport
{
   public static final String TEST_TOKEN = "unit-test-token-abcdef0123456789";
   public static final String OPERATOR   = "operator@example.test";



   /*******************************************************************************
    ** Not instantiable.
    *******************************************************************************/
   private AuthentikTestSupport()
   {
   }



   /*******************************************************************************
    ** A valid config for unit tests (fake host, literal token).
    *******************************************************************************/
   public static AuthentikQBitConfig unitConfig()
   {
      return (new AuthentikQBitConfig()
         .withBaseUrl("https://authentik.example.test")
         .withApiToken(TEST_TOKEN)
         .withAppKey("kof22-admin")
         .withListCacheTtlSeconds(0)
         .withThrottleRequestsPerSecond(1000)
         .withThrottleBurst(1000));
   }



   /*******************************************************************************
    ** A QInstance (MOCK auth) with the qbit produced from the config.
    *******************************************************************************/
   public static QInstance produce(AuthentikQBitConfig config) throws QException
   {
      QInstance qInstance = new QInstance();
      qInstance.withInstanceDefaultAuthentication(new QAuthenticationMetaData().withName("mock").withType(QAuthenticationType.MOCK));
      new AuthentikQBitProducer().withQBitConfig(config).produce(qInstance);
      return (qInstance);
   }



   /*******************************************************************************
    ** Point the qbit's API backend at a different action util class.
    *******************************************************************************/
   public static void useActionUtil(QInstance qInstance, AuthentikQBitConfig config, Class<?> actionUtilClass)
   {
      ((APIBackendMetaData) qInstance.getBackend(config.getApiBackendName())).setActionUtil(new QCodeReference(actionUtilClass));
   }



   /*******************************************************************************
    ** Log in as the operator with the given identity permissions.
    *******************************************************************************/
   public static QSession loginWith(QInstance qInstance, IdentityPermission... permissions)
   {
      Set<String> names = new HashSet<>();
      Arrays.stream(permissions).forEach(p -> names.add(p.getSessionPermission()));
      return (loginWithPermissions(qInstance, names));
   }



   /*******************************************************************************
    ** Log in as the operator with raw QQQ permission names.
    *******************************************************************************/
   public static QSession loginWithPermissions(QInstance qInstance, Set<String> permissionNames)
   {
      QSession session = new QSession();
      session.setUser(new QUser().withIdReference(OPERATOR).withFullName("Test Operator"));
      session.setPermissions(new HashSet<>(permissionNames));
      QContext.init(qInstance, session);
      return (session);
   }



   /*******************************************************************************
    ** Read a classpath resource as text.
    *******************************************************************************/
   public static String resource(String path)
   {
      try(InputStream inputStream = AuthentikTestSupport.class.getClassLoader().getResourceAsStream(path))
      {
         if(inputStream == null)
         {
            throw (new IllegalArgumentException("No such test resource: " + path));
         }
         return (new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
      }
      catch(IOException e)
      {
         throw (new IllegalStateException(e));
      }
   }

}
