// Who started to see a team project (docs/DECISIONS.md "Project contents only for members"): every change that lets
// someone read a project in projects/ (an owner or admin adding themselves, someone added to one of its groups, a new
// account made in one of its groups, a change of its members) leaves an audit row `project.member_gained` (the
// project, the person, how: `via`, and `self` when they did it themselves) and one quiet inbox notice to the project's
// members, "{who} joined '{name}'" (notifications/service.ts project.joined). So nobody, an admin included, reads a
// project without its members being told and the activity log saying so (security review M5).
import type { AppContext } from '../context'
import { audit } from '../admin/audit'
import { atLeast, inProjectZone, type Principal, type RuleSet } from '../policy/access'
import { notificationsOf } from '../notifications/service'

/** What projectJoins compares: the active people (with groups) and the rules, as admin/folders.ts captureState holds them. */
export interface JoinState { principals: readonly Principal[]; rules: RuleSet }

/**
 * Record who started to read each live team project in projects/ between `before` (null: nobody read anything, a new
 * account) and `after`. `by.actor`: who made the change; `by.via`: what it was (project, group, account, role, rules).
 * Never throws: the change is saved already.
 */
export function projectJoins(ctx: AppContext, before: JoinState | null, after: JoinState, by: { actor: string | null; via: string; only?: ReadonlySet<string> }): void {
  try {
    const projects = ctx.db.query("SELECT id, name, folder_path FROM projects WHERE trashed_with IS NULL AND folder_path LIKE 'projects/%'").all() as { id: string; name: string; folder_path: string }[]
    for (const pr of projects) {
      const segs = pr.folder_path.split('/')
      if (segs.length !== 2 || !inProjectZone(segs)) continue
      const reads = (s: JoinState, p: Principal) => atLeast(s.rules.access(p, segs), 'read')
      const was = new Set(before ? before.principals.filter((p) => reads(before, p)).map((p) => p.id) : [])
      const now = after.principals.filter((p) => reads(after, p))
      const gained = now.filter((p) => !was.has(p.id) && (!by.only || by.only.has(p.id)))
      if (!gained.length) continue
      for (const g of gained) {
        const id = audit(ctx.db, { actor: by.actor, action: 'project.member_gained', target: pr.id, detail: { projectId: pr.id, userId: g.id, via: by.via, ...(by.actor === g.id ? { self: true } : {}) } })
        // its members (who saw it before; not the person, not who made the change: they know)
        for (const m of now) {
          if (m.id === g.id || m.id === by.actor || !was.has(m.id)) continue
          try { notificationsOf(ctx).projectJoined(m.id, String(id)) } catch { ctx.log.warn('project join notice failed') }
        }
      }
    }
  } catch (e) { ctx.log.warn('project joins not recorded', { err: e }) }
}

/** A new account (made by an admin, from an invite or the team link) that sees team projects through its groups: the
 * same trail as any other join. Call after the account and its groups are written. */
export function projectJoinsOfNewAccount(ctx: AppContext, userId: string, actor: string | null, now: JoinState): void {
  projectJoins(ctx, { principals: now.principals.filter((p) => p.id !== userId), rules: now.rules }, now, { actor, via: 'account', only: new Set([userId]) })
}
