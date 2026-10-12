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


import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Tests for TokenBucketThrottle, on a fake clock.
 *******************************************************************************/
class TokenBucketThrottleTest
{

   /*******************************************************************************
    ** 10 rps, burst 20: the first 20 calls are free, then each waits 100 ms of
    ** clock time; sleeping advances the fake clock.
    *******************************************************************************/
   @Test
   void defaultTenPerSecondWithBurstTwenty()
   {
      AtomicLong       clock  = new AtomicLong(0);
      List<Long>       sleeps = new ArrayList<>();
      TokenBucketThrottle throttle = new TokenBucketThrottle(10, 20, clock::get, nanos ->
      {
         sleeps.add(nanos);
         clock.addAndGet(nanos);
      });

      for(int i = 0; i < 20; i++)
      {
         throttle.acquire();
      }
      assertThat(sleeps).isEmpty();

      throttle.acquire();
      assertThat(sleeps).hasSize(1);
      assertThat(sleeps.get(0)).isBetween(99_000_000L, 101_000_000L);

      for(int i = 0; i < 9; i++)
      {
         throttle.acquire();
      }
      long total = sleeps.stream().mapToLong(Long::longValue).sum();
      assertThat(total).isBetween(990_000_000L, 1_010_000_000L);
   }



   /*******************************************************************************
    ** Idle time refills, capped at the burst.
    *******************************************************************************/
   @Test
   void refillsWhileIdleUpToBurst()
   {
      AtomicLong          clock    = new AtomicLong(0);
      TokenBucketThrottle throttle = new TokenBucketThrottle(10, 5, clock::get, clock::addAndGet);
      for(int i = 0; i < 5; i++)
      {
         throttle.acquire();
      }
      assertThat(throttle.getAvailableTokens()).isLessThan(0.01);

      clock.addAndGet(60_000_000_000L);
      assertThat(throttle.getAvailableTokens()).isEqualTo(5.0);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   @Test
   void rejectsZeroRate()
   {
      assertThatThrownBy(() -> new TokenBucketThrottle(0, 1)).isInstanceOf(IllegalArgumentException.class);
   }



   /*******************************************************************************
    ** The real clock: a burst of 1 at 1000 rps makes the second call wait a
    ** little, without failing.
    *******************************************************************************/
   @Test
   void systemClockConstructor()
   {
      TokenBucketThrottle throttle = new TokenBucketThrottle(1000, 1);
      long                start    = System.nanoTime();
      throttle.acquire();
      throttle.acquire();
      assertThat(System.nanoTime() - start).isLessThan(1_000_000_000L);
   }

}
