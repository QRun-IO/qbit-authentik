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

package com.kingsrook.qbits.authentik.permissions;


import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import com.kingsrook.qbits.authentik.AuthentikQBitConfig;
import com.kingsrook.qbits.authentik.AuthentikRuntime;
import com.kingsrook.qbits.authentik.client.AuthentikActionUtil;
import com.kingsrook.qbits.authentik.security.IdentityPermission;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.logging.QLogger;
import org.json.JSONObject;
import static com.kingsrook.qqq.backend.core.logging.LogUtils.logPair;


/*******************************************************************************
 ** The cut-over from a host's current permission source to Authentik group
 ** policies (DESIGN.md section 12.8): for every active person, what they get
 ** today (the host source) against what the mapper would grant (their groups'
 ** policies and permissions, the static fallback and bootstrap subjects), and
 ** the guard that keeps the mapper inactive while a member of a guarded group
 ** would lose a permission.
 *******************************************************************************/
public final class AccessComparison
{
   private static final QLogger LOG = QLogger.getLogger(AccessComparison.class);

   /** How long a computed mapper state is reused (sign-ins read it). */
   public static final Duration STATE_TTL = Duration.ofSeconds(60);

   /** Banner shown wherever policies are edited while they are not enforced. */
   public static final String NOT_ENFORCED = "Policies are saved but NOT enforced at sign-in on this instance (mapper off).";



   /*******************************************************************************
    ** One person.
    *******************************************************************************/
   public record Row(int pk, String username, String email, List<String> groups, Set<String> before, Set<String> after,
                     Set<String> added, Set<String> removed, boolean guarded)
   {
   }



   /*******************************************************************************
    ** Whether the mapper is enforcing policies, and why not.
    *******************************************************************************/
   public enum Status
   {
      /** The host does not use the mapper: policies are saved, not enforced. */
      OFF,
      /** Enforced; the guard passed (or there is nothing to guard). */
      ACTIVE,
      /** Enforced because the owner overrode a failing guard. */
      OVERRIDDEN,
      /** Not enforced: the guard failed (or could not run); sign-in uses the host source. */
      BLOCKED
   }



   /*******************************************************************************
    ** A mapper state with a plain message.
    *******************************************************************************/
   public record State(Status status, String message, Instant checkedAt)
   {
      /*******************************************************************************
       ** Whether sign-in permissions come from the policies.
       *******************************************************************************/
      public boolean enforced()
      {
         return (status == Status.ACTIVE || status == Status.OVERRIDDEN);
      }
   }



   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AccessComparison()
   {
   }



   /*******************************************************************************
    ** Compare every active person (internal and external users).
    *******************************************************************************/
   public static List<Row> run(AuthentikQBitConfig config, AuthentikActionUtil util, Collection<String> catalog) throws QException
   {
      GroupGraph                  graph    = util.groupGraphWithMembers();
      EffectivePermissionResolver resolver = new EffectivePermissionResolver(graph, catalog);
      AuthentikHostPermissionSource source = config.getHostPermissionSource();
      List<Row>                   rows     = new ArrayList<>();
      for(JSONObject user : util.allUsers())
      {
         String type = user.optString("type");
         if(!user.optBoolean("is_active", true) || !("internal".equals(type) || "external".equals(type)))
         {
            continue;
         }
         int          pk       = user.optInt("pk");
         List<String> groupPks = graph.groupsOfUser(pk);
         List<String> names    = new ArrayList<>();
         for(String groupPk : groupPks)
         {
            names.add(graph.byPk(groupPk).name());
         }
         String      email  = user.optString("email", null);
         Set<String> before = new TreeSet<>(source == null ? Set.of() : source.userPermissions(email, names));
         Set<String> after  = mapperPermissions(config, resolver, groupPks, names, String.valueOf(pk), user.optString("uuid"));
         Set<String> added  = new TreeSet<>(after);
         added.removeAll(before);
         Set<String> removed = new TreeSet<>(before);
         removed.removeAll(after);
         boolean guarded = names.stream().anyMatch(n -> config.getCutoverGuardGroups() != null && config.getCutoverGuardGroups().contains(n));
         rows.add(new Row(pk, user.optString("username"), email, names, before, after, added, removed, guarded));
      }
      return (rows);
   }



   /*******************************************************************************
    ** What the mapper grants for a person's direct groups: the groups' (and
    ** ancestors') qqq.io/permissions and policies, the static fallback of the
    ** direct groups, and every authentik.* permission for a bootstrap subject.
    *******************************************************************************/
   public static Set<String> mapperPermissions(AuthentikQBitConfig config, EffectivePermissionResolver resolver, Collection<String> groupPks, Collection<String> directGroupNames,
      String userPk, String userUuid)
   {
      return (mapperPermissions(config, resolver, groupPks, directGroupNames, userPk, userUuid, null));
   }



   /*******************************************************************************
    ** Preview the mapper with one group's policy removed, preserving the
    ** static floor and immutable bootstrap-subject grants.
    *******************************************************************************/
   public static Set<String> mapperPermissions(AuthentikQBitConfig config, EffectivePermissionResolver resolver, Collection<String> groupPks, Collection<String> directGroupNames,
      String userPk, String userUuid, String excludePolicyOfGroupPk)
   {
      Set<String> rs = new TreeSet<>(resolver.resolveGroups(groupPks, excludePolicyOfGroupPk).sessionPermissions());
      rs.addAll(staticPermissions(config, directGroupNames));
      Set<String> subjects = config.getResolvedBootstrapSubjects();
      if(subjects.contains(userPk) || (userUuid != null && !userUuid.isEmpty() && subjects.contains(userUuid)))
      {
         for(IdentityPermission permission : IdentityPermission.values())
         {
            rs.add(permission.getSessionPermission());
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** The static fallback permissions of some direct groups.
    *******************************************************************************/
   public static Set<String> staticPermissions(AuthentikQBitConfig config, Collection<String> directGroupNames)
   {
      Set<String> rs = new TreeSet<>();
      if(config.getStaticGroupPermissions() != null)
      {
         for(String name : directGroupNames)
         {
            rs.addAll(config.getStaticGroupPermissions().getOrDefault(name, List.of()));
         }
      }
      return (rs);
   }



   /*******************************************************************************
    ** The people in guarded groups who would lose a permission (the guard fails
    ** when this is not empty).
    *******************************************************************************/
   public static List<Row> guardFailures(List<Row> rows)
   {
      return (rows.stream().filter(r -> r.guarded() && !r.removed().isEmpty()).toList());
   }



   /*******************************************************************************
    ** The mapper state of a backend (cached for STATE_TTL; sign-ins read it).
    *******************************************************************************/
   public static State state(AuthentikRuntime runtime, AuthentikActionUtil util)
   {
      State cached = runtime.getMapperState();
      if(cached != null && cached.checkedAt().plus(STATE_TTL).isAfter(Instant.now()))
      {
         return (cached);
      }
      State state = compute(runtime, util);
      runtime.setMapperState(state);
      return (state);
   }



   /*******************************************************************************
    ** Compute the mapper state now.
    *******************************************************************************/
   static State compute(AuthentikRuntime runtime, AuthentikActionUtil util)
   {
      AuthentikQBitConfig config = runtime.getConfig();
      if(!Boolean.TRUE.equals(config.getMapperEnabled()) && !runtime.isMapperInvoked())
      {
         return (new State(Status.OFF, NOT_ENFORCED, Instant.now()));
      }
      if(config.getCutoverGuardGroups() == null || config.getCutoverGuardGroups().isEmpty())
      {
         return (new State(Status.ACTIVE, "Policies are enforced at sign-in.", Instant.now()));
      }
      if(Boolean.TRUE.equals(config.getMapperOverride()))
      {
         return (new State(Status.OVERRIDDEN, "Policies are enforced at sign-in; the cut-over guard is overridden by the owner.", Instant.now()));
      }
      try
      {
         List<Row> failures = guardFailures(run(config, util, runtime.getPermissionCatalog()));
         if(failures.isEmpty())
         {
            return (new State(Status.ACTIVE, "Policies are enforced at sign-in; the cut-over guard passed (no member of "
               + String.join(", ", config.getCutoverGuardGroups()) + " loses a permission).", Instant.now()));
         }
         List<String> names = failures.stream().map(Row::username).limit(5).toList();
         return (new State(Status.BLOCKED, "Policies are saved but NOT enforced at sign-in: the cut-over guard found " + failures.size() + " member(s) of "
            + String.join(", ", config.getCutoverGuardGroups()) + " who would lose permissions (" + String.join(", ", names)
            + "). Sign-in keeps today's access until the policies cover it, or the owner overrides the guard.", Instant.now()));
      }
      catch(Exception e)
      {
         LOG.warn("The cut-over guard could not run; the mapper stays inactive", logPair("error", e.getMessage()));
         return (new State(Status.BLOCKED, "Policies are saved but NOT enforced at sign-in: the cut-over guard could not check Authentik ("
            + e.getMessage() + "). Sign-in keeps today's access.", Instant.now()));
      }
   }
}
