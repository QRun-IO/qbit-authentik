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

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import com.kingsrook.qbits.authentik.AuthentikTestSupport;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Real SQL transactions exercise duplicate races, lease fencing and retries.
 ** Unique ephemeral H2 databases isolate each test from other agents' work.
 *******************************************************************************/
@Timeout(30)
class AuthentikWebhookInboxTest
{
   private DataSource source;
   private AuthentikWebhookInbox inbox;

   /*******************************************************************************
    ** Each processor instance shares only persisted database state.
    *******************************************************************************/
   private AuthentikWebhookInbox processor()
   {
      return (new AuthentikWebhookInbox(source, AuthentikTestSupport.unitConfig().withLocalBackendName("hostLocal"), Duration.ofMinutes(5)));
   }

   /*******************************************************************************
    ** Install exactly the host migration, not a test-specific queue schema.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      source = createDataSource();
      sql(Files.readString(Path.of("docs/schema-sync.sql")));
      inbox = processor();
   }

   /*******************************************************************************
    ** Remove only this test's private database objects.
    *******************************************************************************/
   @AfterEach
   void tearDown() throws SQLException
   {
      sql(cleanupSql());
   }

   /*******************************************************************************
    ** Overridden by the PostgreSQL contract to run the identical race suite.
    *******************************************************************************/
   protected DataSource createDataSource() throws SQLException
   {
      JdbcDataSource dataSource = new JdbcDataSource();
      dataSource.setURL("jdbc:h2:mem:qbit_authentik_inbox_" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000");
      return (dataSource);
   }

   /*******************************************************************************
    ** Cleanup is scoped to the private database/schema allocated by this test.
    *******************************************************************************/
   protected String cleanupSql()
   {
      return ("DROP ALL OBJECTS");
   }

   /*******************************************************************************
    ** Synthetic validated hint.
    *******************************************************************************/
   private AuthentikWebhookEnvelope event()
   {
      return (new AuthentikWebhookEnvelope(UUID.randomUUID().toString(), "model_updated", Instant.parse("2026-11-04T12:00:00Z"),
         "synthetic", "authentik_core", "user", "123", "authentik_core"));
   }

   /*******************************************************************************
    ** Test-only time advancement via persisted timestamps, with no sleeps.
    *******************************************************************************/
   private void sql(String sql) throws SQLException
   {
      try(var connection = source.getConnection(); var statement = connection.createStatement())
      {
         statement.execute(sql);
      }
   }

   /*******************************************************************************
    ** Scalar observation from the authoritative queue state.
    *******************************************************************************/
   private String scalar(String expression) throws SQLException
   {
      try(var connection = source.getConnection(); var statement = connection.createStatement();
         var result = statement.executeQuery("SELECT " + expression + " FROM authentik_webhook_inbox"))
      {
         result.next();
         return (result.getString(1));
      }
   }

   /*******************************************************************************
    ** Concurrent deliveries commit one row and never replace its payload.
    *******************************************************************************/
   @Test
   void duplicateDeliverySurvivesConcurrentReceiversAndRestart() throws Exception
   {
      var event = event();
      try(var workers = Executors.newFixedThreadPool(8))
      {
         List<Callable<Boolean>> receives = new ArrayList<>();
         for(int i = 0; i < 32; i++)
         {
            receives.add(() -> processor().accept(event));
         }
         int inserted = 0;
         for(var result : workers.invokeAll(receives))
         {
            inserted += result.get() ? 1 : 0;
         }
         assertThat(inserted).isEqualTo(1);
      }
      assertThat(scalar("COUNT(*)")).isEqualTo("1");
      assertThat(processor().accept(new AuthentikWebhookEnvelope(event.eventPk().toUpperCase(java.util.Locale.ROOT), "login", event.created(),
         "different", null, null, null, null))).isFalse();
      assertThat(scalar("payload_json")).contains("model_updated").doesNotContain("different");
      assertThat(processor().claim(1)).hasSize(1);
      assertThat(inbox.claim(1)).isEmpty();
   }

   /*******************************************************************************
    ** Competing processors cannot own the same live claim; stale completion,
    ** renewal and failure are all fenced after another processor reclaims it.
    *******************************************************************************/
   @Test
   void claimsAreExclusiveAndExpiredWorkersCannotOverwrite() throws Exception
   {
      inbox.accept(event());
      List<AuthentikWebhookInbox.Claim> claims = new ArrayList<>();
      try(var workers = Executors.newFixedThreadPool(8))
      {
         List<Callable<List<AuthentikWebhookInbox.Claim>>> attempts = new ArrayList<>();
         for(int i = 0; i < 8; i++)
         {
            attempts.add(() -> processor().claim(1));
         }
         for(var result : workers.invokeAll(attempts))
         {
            claims.addAll(result.get());
         }
      }
      assertThat(claims).hasSize(1);
      var old = claims.get(0);
      sql("UPDATE authentik_webhook_inbox SET lease_until=TIMESTAMP WITH TIME ZONE '2000-01-01 00:00:00Z'");
      var current = processor().claim(1).get(0);
      assertThat(current.attempt()).isEqualTo(2);
      assertThat(inbox.complete(old)).isFalse();
      assertThat(inbox.fail(old)).isFalse();
      assertThat(inbox.renew(old)).isFalse();
      assertThat(inbox.withClaim(old, connection -> { throw new AssertionError("Stale worker reached mirror writes"); })).isFalse();
      assertThat(inbox.renew(current)).isTrue();
      assertThat(inbox.complete(current)).isTrue();
      assertThat(scalar("status")).isEqualTo("SUCCEEDED");
   }

   /*******************************************************************************
    ** Backoff is persisted, and a fifth failure is terminal across restarts.
    *******************************************************************************/
   @Test
   void retriesAreBoundedAndPersistNoExceptionDetails() throws Exception
   {
      inbox.accept(event());
      AtomicInteger calls = new AtomicInteger();
      for(int attempt = 1; attempt <= 5; attempt++)
      {
         var runner = new AuthentikApplyChangeEvents(processor(), (ignored, claim) ->
         {
            calls.incrementAndGet();
            throw new IllegalStateException("synthetic-secret-must-not-be-stored");
         });
         assertThat(runner.runBatch()).isEqualTo(new AuthentikApplyChangeEvents.Result(0, 1, 0, 0));
         assertThat(inbox.claim(1)).isEmpty();
         assertThat(scalar("attempts")).isEqualTo(Integer.toString(attempt));
         assertThat(scalar("error_code")).isEqualTo("PROCESSING_FAILED");
         sql("UPDATE authentik_webhook_inbox SET next_attempt_at=TIMESTAMP WITH TIME ZONE '2000-01-01 00:00:00Z'");
      }
      assertThat(calls.get()).isEqualTo(5);
      assertThat(scalar("status")).isEqualTo("FAILED");
      assertThat(inbox.claim(1)).isEmpty();
   }

   /*******************************************************************************
    ** A crash on the final attempt cannot leave permanently running work.
    *******************************************************************************/
   @Test
   void expiredFinalAttemptBecomesTerminal() throws Exception
   {
      inbox.accept(event());
      inbox.claim(1);
      sql("UPDATE authentik_webhook_inbox SET attempts=5,lease_until=TIMESTAMP WITH TIME ZONE '2000-01-01 00:00:00Z'");
      assertThat(processor().claim(1)).isEmpty();
      assertThat(scalar("status")).isEqualTo("FAILED");
      assertThat(scalar("error_code")).isEqualTo("LEASE_EXPIRED");
   }

   /*******************************************************************************
    ** Retention removes only terminal old rows, preserving unprocessed work.
    ** One batch is bounded to fifty even when the queue is larger.
    *******************************************************************************/
   @Test
   void successfulBatchAndRetentionPreserveUnfinishedWork() throws Exception
   {
      for(int i = 0; i < 51; i++)
      {
         inbox.accept(event());
      }
      AtomicInteger calls = new AtomicInteger();
      var runner = new AuthentikApplyChangeEvents(inbox, (ignored, claim) -> calls.incrementAndGet());
      assertThat(runner.runBatch()).isEqualTo(new AuthentikApplyChangeEvents.Result(50, 0, 0, 0));
      assertThat(calls.get()).isEqualTo(50);
      assertThat(inbox.purge()).isZero();
      sql("UPDATE authentik_webhook_inbox SET received_at=TIMESTAMP WITH TIME ZONE '2000-01-01 00:00:00Z',processed_at=TIMESTAMP WITH TIME ZONE '2000-01-01 00:00:00Z'");
      assertThat(inbox.purge()).isEqualTo(50);
      assertThat(scalar("COUNT(*)")).isEqualTo("1");
      assertThat(scalar("status")).isEqualTo("PENDING");
      assertThat(runner.runBatch().succeeded()).isEqualTo(1);
   }

   /*******************************************************************************
    ** Storage outages cannot be mistaken for already-persisted deliveries.
    *******************************************************************************/
   @Test
   void unavailableStorageAndInvalidBoundsFailClosed() throws Exception
   {
      assertThatThrownBy(() -> inbox.claim(51)).isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> processor().claim(0)).isInstanceOf(IllegalArgumentException.class);
      sql("DROP TABLE authentik_webhook_inbox");
      assertThatThrownBy(() -> inbox.accept(event())).isInstanceOf(SQLException.class);
   }

   /*******************************************************************************
    ** The lease check and local writes are atomic; a failed projection cannot
    ** publish half a mirror snapshot or leave the connection uncommitted.
    *******************************************************************************/
   @Test
   void localWorkRollsBackAndCanBeReplayed() throws Exception
   {
      inbox.accept(event());
      var claim = inbox.claim(1).get(0);
      AuthentikWebhookInbox.LocalWork insert = connection ->
      {
         try(var statement = connection.prepareStatement("INSERT INTO authentik_user_mirror(pk,username,refreshed_at) VALUES (123,'synthetic',CURRENT_TIMESTAMP)"))
         {
            statement.executeUpdate();
         }
      };
      assertThatThrownBy(() -> inbox.withClaim(claim, connection ->
      {
         insert.apply(connection);
         throw new IllegalStateException("Fail before commit");
      })).isInstanceOf(IllegalStateException.class);
      // This unique-key insert can succeed only if the first write rolled back.
      assertThat(inbox.withClaim(claim, insert)).isTrue();
      assertThat(inbox.complete(claim)).isTrue();
      assertThat(inbox.withClaim(claim, connection -> { throw new AssertionError("Completed work ran again"); })).isFalse();
   }
}
