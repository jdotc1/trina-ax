// Once, at the first start of the build that makes team projects members only (docs/DECISIONS.md "Project contents only
// for members"). Access itself changes with the code (policy/access.ts: the members-only zone); these steps take away
// what the owner and admins kept from before, when they read every project by their role. Each is idempotent, the
// whole runs once (a settings key), and one audit row says what it did.
//   1. Shared project chats: who saw a chat when an answer read what it used (chat/shared-answers.ts, `c`) included every
//      owner and admin by role. They are taken out, so an answer is theirs again only if it was their own turn or they
//      read everything it used now (fails closed).
//   2. Role rules for the owner or admins inside projects/<name>/ have no effect any more (they are judged as members):
//      removed, so the members list never shows a rule that does nothing.
//   3. Scheduled tasks whose card counted the owner and admins as readers of a project (a save folder or a place under
//      projects/): their save permission lapses once ('rules'), and their person answers the card again.
//   4. The owner's and admins' AI sessions start fresh: a resumed session must not keep project text read before.
import type { AppContext } from '../context'
import { audit } from '../admin/audit'
import { getSetting, setSetting } from '../admin/settings'
import { inZone } from '../policy/zone'
import type { ScheduleRow } from './schedules'

const DONE = 'projectsMembersOnly.v1'

export async function membersOnlyOnce(ctx: AppContext): Promise<void> {
  try {
    if (getSetting(ctx.db, DONE)) return
    // (loaded here, not at the top: context.ts runs this at start, before those modules may be imported)
    const { markLapsed } = await import('./schedule-scope')
    const { resetEngineSessions } = await import('./runtime')
    const db = ctx.db
    const staff = new Set((db.query("SELECT id FROM users WHERE role IN ('owner', 'admin')").all() as { id: string }[]).map((u) => u.id))
    // 1. shared answers of projects in projects/
    let answers = 0
    const rows = db.query(`SELECT r.message_id, r.reads FROM shared_answer_reads r JOIN chats c ON c.id = r.chat_id JOIN projects p ON p.id = c.project_id
      WHERE p.folder_path LIKE 'projects/%'`).all() as { message_id: string; reads: string | null }[]
    db.transaction(() => {
      for (const r of rows) {
        let groups: { c?: unknown }[]
        try { groups = JSON.parse(r.reads ?? 'null') } catch { continue }
        if (!Array.isArray(groups)) continue
        let changed = false
        for (const g of groups) {
          if (!g || !Array.isArray(g.c)) continue
          const kept = (g.c as unknown[]).filter((id) => !(typeof id === 'string' && staff.has(id)))
          if (kept.length !== g.c.length) { g.c = kept; changed = true }
        }
        if (changed) { db.query('UPDATE shared_answer_reads SET reads = ? WHERE message_id = ?').run(JSON.stringify(groups), r.message_id); answers++ }
      }
    })()
    // 2. role rules for the owner or admins inside the zone
    const roleRules = db.query(`SELECT r.id, f.path, r.subject_id FROM folder_rules r JOIN folders f ON f.id = r.folder_id
      WHERE r.subject_type = 'role' AND r.subject_id IN ('owner', 'admin')`).all() as { id: string; path: string; subject_id: string }[]
    const gone = roleRules.filter((r) => inZone(r.path))
    if (gone.length) db.transaction(() => { for (const r of gone) db.query('DELETE FROM folder_rules WHERE id = ?').run(r.id) })()
    // 3. scheduled tasks with a save folder or a place under projects/
    let schedules = 0
    const folderPath = (id: string) => (db.query('SELECT path FROM folders WHERE id = ?').get(id) as { path: string } | null)?.path ?? null
    for (const s of db.query('SELECT id, user_id, save_folder, save_sources FROM schedules WHERE save_folder IS NOT NULL AND save_lapsed_at IS NULL').all() as (Pick<ScheduleRow, 'id' | 'user_id' | 'save_folder'> & { save_sources: string | null })[]) {
      let sources: { type?: string; id?: string }[] = []
      try { sources = JSON.parse(s.save_sources ?? '[]') } catch { sources = [] }
      const touches = (s.save_folder && inZone(s.save_folder)) || (Array.isArray(sources) && sources.some((x) => x?.type === 'folder' && typeof x.id === 'string' && inZone(folderPath(x.id) ?? '')))
      if (touches && markLapsed(ctx, s, 'rules')) schedules++
    }
    // 4. fresh AI sessions for the owner and admins
    let sessions = 0
    for (const id of staff) { try { sessions += resetEngineSessions(ctx, id) } catch { /* their next turn starts fresh anyway when it cannot resume */ } }
    setSetting(db, DONE, new Date().toISOString())
    // (a new team, or one with nothing to take away: no row)
    if (answers || gone.length || schedules || sessions) audit(db, { actor: null, action: 'projects.members_only', target: null, detail: { answers, roleRules: gone.map((r) => ({ path: r.path, role: r.subject_id })), schedules, sessions } })
  } catch (e) { ctx.log.error('the members-only start steps did not finish; they run again at the next start', { err: e }) }
}
