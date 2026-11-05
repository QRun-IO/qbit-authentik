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

import java.sql.SQLException;
import java.util.UUID;
import javax.sql.DataSource;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;

/*******************************************************************************
 ** The same inbox race/retry tests against actual PostgreSQL. Uses a separate
 ** uniquely named host database container, never Authentik's database.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
class AuthentikWebhookInboxPostgresIT extends AuthentikWebhookInboxTest
{
   private static PostgreSQLContainer<?> postgres;
   private String schema;

   /*******************************************************************************
    ** Loopback-only disposable database with explicit unique ownership.
    *******************************************************************************/
   @BeforeAll
   static void startDatabase()
   {
      String owner = "qbit-authentik-inbox-" + UUID.randomUUID().toString().substring(0, 8);
      postgres = new PostgreSQLContainer<>(System.getProperty("postgres.test.image", "postgres:16-alpine"))
         .withDatabaseName("qbit_inbox_contract")
         .withLabel("io.qrun.qbit.project", "qbit-authentik")
         .withLabel("io.qrun.qbit.contract", owner)
         .withCreateContainerCmdModifier(command ->
         {
            command.withName(owner);
            command.getHostConfig().withPortBindings(new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(5432)));
         });
      try
      {
         postgres.start();
      }
      catch(RuntimeException failure)
      {
         postgres.stop();
         throw (failure);
      }
   }

   /*******************************************************************************
    ** Stop this exact Testcontainers instance, never any other agent's stack.
    *******************************************************************************/
   @AfterAll
   static void stopDatabase()
   {
      if(postgres != null)
      {
         postgres.stop();
      }
   }

   /*******************************************************************************
    ** Each inherited test executes the real migration in its own SQL schema.
    *******************************************************************************/
   @Override
   protected DataSource createDataSource() throws SQLException
   {
      PGSimpleDataSource source = new PGSimpleDataSource();
      source.setURL(postgres.getJdbcUrl());
      source.setUser(postgres.getUsername());
      source.setPassword(postgres.getPassword());
      schema = "inbox_" + UUID.randomUUID().toString().replace("-", "");
      try(var connection = source.getConnection(); var statement = connection.createStatement())
      {
         statement.execute("CREATE SCHEMA " + schema);
      }
      source.setCurrentSchema(schema);
      return (source);
   }

   /*******************************************************************************
    ** Generated schema name is owned by this test and contains only hex digits.
    *******************************************************************************/
   @Override
   protected String cleanupSql()
   {
      return ("DROP SCHEMA " + schema + " CASCADE");
   }
}
