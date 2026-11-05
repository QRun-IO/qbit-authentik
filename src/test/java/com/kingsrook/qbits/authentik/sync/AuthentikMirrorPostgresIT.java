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

import java.util.UUID;
import javax.sql.DataSource;
import com.kingsrook.qbits.authentik.RequiresDockerCondition;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.module.postgres.model.metadata.PostgreSQLBackendMetaData;
import com.kingsrook.qqq.backend.module.postgres.model.metadata.PostgreSQLTableBackendDetails;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;

/*******************************************************************************
 ** Host mirror/audit transactions through QQQ's real PostgreSQL backend module.
 ** This database is separate from Authentik and from the user's review stack.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
class AuthentikMirrorPostgresIT extends AuthentikMirrorSqlTest
{
   private static PostgreSQLContainer<?> postgres;
   private String schema;

   /*******************************************************************************
    ** Unique ownership and loopback-only exposure for shared agent hosts.
    *******************************************************************************/
   @BeforeAll
   static void start()
   {
      String owner = "qbit-authentik-mirror-" + UUID.randomUUID().toString().substring(0, 8);
      postgres = new PostgreSQLContainer<>(System.getProperty("postgres.test.image", "postgres:16-alpine"))
         .withDatabaseName("qbit_mirror_contract")
         .withLabel("io.qrun.qbit.project", "qbit-authentik").withLabel("io.qrun.qbit.contract", owner)
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
    ** Remove only this contract's exact container.
    *******************************************************************************/
   @AfterAll
   static void stop()
   {
      if(postgres != null)
      {
         postgres.stop();
      }
   }

   /*******************************************************************************
    ** Separate schema per inherited test, within the owned host database.
    *******************************************************************************/
   @Override
   protected DataSource createSource(String owner) throws Exception
   {
      PGSimpleDataSource source = new PGSimpleDataSource();
      source.setURL(postgres.getJdbcUrl());
      source.setUser(postgres.getUsername());
      source.setPassword(postgres.getPassword());
      source.setOptions("-c TimeZone=America/Chicago");
      schema = owner;
      try(var connection = source.getConnection(); var statement = connection.createStatement())
      {
         statement.execute("CREATE SCHEMA " + schema);
      }
      source.setCurrentSchema(schema);
      return (source);
   }

   /*******************************************************************************
    ** Use PostgreSQL's QQQ strategy, not H2 or generic JDBC for mirror writes.
    *******************************************************************************/
   @Override
   protected QBackendMetaData backend(String owner, DataSource source)
   {
      PostgreSQLBackendMetaData backend = new PostgreSQLBackendMetaData().withName(owner)
         .withHostName(postgres.getHost()).withPort(postgres.getFirstMappedPort()).withDatabaseName(postgres.getDatabaseName())
         .withUsername(postgres.getUsername()).withPassword(postgres.getPassword());
      backend.setJdbcUrl(postgres.getJdbcUrl() + (postgres.getJdbcUrl().contains("?") ? "&" : "?") + "currentSchema=" + schema
         + "&options=-c%20TimeZone%3DAmerica%2FChicago");
      return (backend);
   }

   /*******************************************************************************
    ** Retain the explicit production column mapping with PostgreSQL details.
    *******************************************************************************/
   @Override
   protected void enrich(QTableMetaData table)
   {
      super.enrich(table);
      table.withBackendDetails(new PostgreSQLTableBackendDetails().withTableName(snake(table.getName())));
   }

   /*******************************************************************************
    ** Schema was generated and created by this exact test instance.
    *******************************************************************************/
   @Override
   protected String cleanupSql()
   {
      return ("DROP SCHEMA " + schema + " CASCADE");
   }
}
