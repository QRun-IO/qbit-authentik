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


import java.util.function.LongConsumer;
import java.util.function.LongSupplier;


/*******************************************************************************
 ** Self-imposed client-side rate limit (DESIGN.md section 9.3). Authentik does
 ** not throttle authenticated API calls at all, and kof22's Authentik shares the
 ** website's Postgres, so the qbit limits itself: a token bucket refilled at
 ** requestsPerSecond, holding at most burst tokens. acquire() blocks until a
 ** token is available. Shared by all requests of one qbit instance.
 *******************************************************************************/
public class TokenBucketThrottle
{
   private final double       tokensPerNano;
   private final double       burst;
   private final LongSupplier nanoClock;
   private final LongConsumer nanoSleeper;

   private double tokens;
   private long   lastRefillNanos;



   /*******************************************************************************
    ** Constructor using the system clock.
    *******************************************************************************/
   public TokenBucketThrottle(int requestsPerSecond, int burst)
   {
      this(requestsPerSecond, burst, System::nanoTime, TokenBucketThrottle::sleepNanos);
   }



   /*******************************************************************************
    ** Constructor with an injectable clock and sleeper (for tests).
    *******************************************************************************/
   public TokenBucketThrottle(int requestsPerSecond, int burst, LongSupplier nanoClock, LongConsumer nanoSleeper)
   {
      if(requestsPerSecond < 1)
      {
         throw (new IllegalArgumentException("requestsPerSecond must be at least 1"));
      }
      this.tokensPerNano = requestsPerSecond / 1_000_000_000.0;
      this.burst = Math.max(1, burst);
      this.nanoClock = nanoClock;
      this.nanoSleeper = nanoSleeper;
      this.tokens = this.burst;
      this.lastRefillNanos = nanoClock.getAsLong();
   }



   /*******************************************************************************
    ** Take one token, waiting as long as needed.
    *******************************************************************************/
   public void acquire()
   {
      long waitNanos;
      synchronized(this)
      {
         refill();
         tokens -= 1;
         waitNanos = tokens >= 0 ? 0 : (long) Math.ceil(-tokens / tokensPerNano);
      }

      if(waitNanos > 0)
      {
         nanoSleeper.accept(waitNanos);
      }
   }



   /*******************************************************************************
    ** Tokens currently available (may be negative while callers are waiting).
    *******************************************************************************/
   public synchronized double getAvailableTokens()
   {
      refill();
      return (tokens);
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private void refill()
   {
      long now     = nanoClock.getAsLong();
      long elapsed = now - lastRefillNanos;
      if(elapsed > 0)
      {
         tokens = Math.min(burst, tokens + elapsed * tokensPerNano);
         lastRefillNanos = now;
      }
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static void sleepNanos(long nanos)
   {
      try
      {
         Thread.sleep(nanos / 1_000_000, (int) (nanos % 1_000_000));
      }
      catch(InterruptedException e)
      {
         Thread.currentThread().interrupt();
      }
   }

}
