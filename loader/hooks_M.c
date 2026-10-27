/* Hook batch M (errata round 2: attacks, Avatar traits, overworld). Built by research/build_hooks_M.py
 * (research/hooks_M.json). Included by hooks.c after hooks_E.c / hooks_B2.c; reuses RValue / GmlScript / VarGet / RVA /
 * CmpInt / ToBool and hooks_E.c's e_var / e_is_enemy / e_truthy / e_call / e_set_bool, hooks_B2.c's b2_num.
 * Every hook keeps the exact signature of the callee it stands in for and falls back to the original behaviour when
 * anything is unexpected. Game addresses are 2.0.38 VAs rebased with RVA(); our state lives in 0x149ed8258-0x149ed82ff.
 * A hook reads its caller's frame as (char *)_AddressOfReturnAddress() + 8 (the caller's rsp at the call). */

#define M_WIGHT_FLAG    0x149ed8298    /* int: SU-0268 used the Wight base at L147 of this resurrection */
#define M_BLACK_PASS    0x149ed829c    /* byte: SU-0280 The Black, 0 = your holder, 1 = the enemy holder */
#define M_BLACK_MORE    0x149ed829d    /* byte: SU-0280 The Black, an enemy pass follows your side's pass */

#define M_RELEASE       0x14028c220    /* runtime: release a temp value */
#define M_MAKE_STR      0x14028c360    /* runtime: value from a global string constant */
#define M_EQ            0x14028c8d0    /* runtime: a == b */
#define M_SUB_INT       0x1402c47f0    /* runtime: out = in - n */
#define M_CALL_BUILTIN  0x147898420    /* runtime: call a builtin by id (self, other, out, argc, id, args) */
#define M_INSTANCE_EXISTS_ID 0x1499e0dc8   /* builtin id slot of instance_exists */
#define M_CUR_SELF      0x1499eadc8    /* the runtime's current-self pointer (every script sets it on entry) */
#define M_RACE_VAR      0x1499e0688
#define M_HPMAX_VAR     0x1499e0b68
#define M_FINISHED_VAR  0x149940b08    /* obj_realmselector.finished */
#define M_HOUND_STR     0x149d607f0    /* global "Hound" */
#define M_WIGHT_STR     0x149d63110    /* global "Wight" */
#define M_GET_REF       0x140297c10    /* runtime: instance / global variable value pointer (instance, var id) */
#define M_HAS_CONDITION 0x14202b010    /* scr_CritHasCondition(creature, condition) */
#define M_DIMINISH      0x1460713c0    /* scr_Diminish */
#define M_ART_OWNER     0x141cdf170    /* inv_ArtifactGetOwner(item) */
#define M_NETHER_STAT   0x141d97fd0    /* inv_NetherStoneGetStat(stone, property) */
#define M_ANY_ALLY      0x141f0a8a0    /* scr_AnyAllyHasPassive */
#define M_ANY_ENEMY     0x141f0b2d0    /* scr_AnyEnemyHasPassive */

typedef void (*MRelease)(RValue *v);
typedef RValue *(*MMakeStr)(RValue *out, void *global);
typedef char (*MCmp2)(RValue *a, RValue *b);
typedef RValue *(*MSubInt)(RValue *out, RValue *in, int n);
typedef RValue *(*MCallBuiltin)(void *self, void *other, RValue *out, int argc, int id, RValue **args);
typedef RValue *(*MGetRef)(void *inst, int var_id);

static void m_real(RValue *v, double x) { memset(v, 0, sizeof *v); v->v.real = x; }

/* creature.race == the game's global race string */
static int m_race_is(RValue *creature, unsigned long long str_global)
{
    RValue race = e_var(creature, M_RACE_VAR), name, *n;
    int same;
    memset(&name, 0, sizeof name);
    n = ((MMakeStr)RVA(M_MAKE_STR))(&name, RVA(str_global));
    same = ((MCmp2)RVA(M_EQ))(&race, n ? n : &name) != 0;
    ((MRelease)RVA(M_RELEASE))(&name);
    ((MRelease)RVA(M_RELEASE))(&race);
    return same;
}

/* scr_CritHasCondition(creature, condition) */
static int m_has_condition(void *self, void *other, RValue *creature, double cond)
{
    RValue c, *a[2];
    m_real(&c, cond);
    a[0] = creature; a[1] = &c;
    return e_call(M_HAS_CONDITION, self, other, 2, a);
}

/* ===== SU-0301 Roulette: cave stub only, no C hook (research/build_hooks_M.py). The heal branch's own `return`
 * (bc_CreatureAttack L1776 marker, not the return tail it shares with the L176 exit) jumps to a stub that runs L1789
 * and joins the per-hit end at L1871, the point a hit that dealt no damage reaches. ===== */

/* ===== SU-0286 Master of Hounds: "Your Hounds' Dire Wolves now deal damage based on their highest stat". The L1067
 * gate in bc_OnAttack had only the side test; the Dire Wolves' owner is the attacker, bc_OnAttack's [frame + 0x168f0].
 * These stand in for its two side calls (scr_AnyEnemyHasPassive / scr_AnyAllyHasPassive(1447)). ===== */
static RValue *m_hound(char *frame, unsigned long long side_fn, void *self, void *other, RValue *ret, int argc,
                       RValue **args)
{
    if (!m_race_is((RValue *)(frame + 0x168f0), M_HOUND_STR)) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(side_fn))(self, other, ret, argc, args);
}
static RValue *hook_m_su0286_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return m_hound((char *)_AddressOfReturnAddress() + 8, M_ANY_ENEMY, self, other, ret, argc, args); }
static RValue *hook_m_su0286_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return m_hound((char *)_AddressOfReturnAddress() + 8, M_ANY_ALLY, self, other, ret, argc, args); }

/* ===== SU-0243 Teleportation Shrine: "It costs 1000 Power to travel to the selected Realm." obj_realmselector
 * KeyPress_69 runs twice (the Step countdown re-enters it once the loading screen exists); the second pass re-checked
 * `ppower - 1000 < 0` (L52) after L57-L59 had already paid (finished = true), so 1,000-1,999 Power paid and failed.
 * Stands in for that subtraction: once paid, subtract 0 (the check passes; the payment itself stays guarded by
 * `finished`). The event's self is its rcx home slot, [frame + 0x490]. ===== */
static RValue *hook_m_su0243_cost(RValue *out, RValue *in, int n)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    void *self = *(void **)(frame + 0x490);
    if (self) {
        RValue *fin = ((MGetRef)RVA(M_GET_REF))(self, *(int *)RVA(M_FINISHED_VAR));
        int ok = 0; double f = fin ? b2_num(fin, &ok) : 0.0;
        if (fin && ok && f != 0.0) n = 0;
    }
    return ((MSubInt)RVA(M_SUB_INT))(out, in, n);
}

/* ===== SU-0268 Forbearance + Master of Wights. Master of Wights: "Your Wights always resurrect with 100% Health";
 * Forbearance: "resurrected with 100% additional Health ... Maximum Health increases by the difference".
 * bc_EventResurrect L147 computes amount = scr_Diminish(amount, bonus) (the bonus pool holds Forbearance's +amount and
 * the card terms, each a multiple of amount), then L150-L152 overwrote amount with Max Health for a Wight. Now the
 * Wight's Max Health is the base at L147 (the pool scaled to it), and the L151 race test reports "not a Wight" so L152
 * no longer throws the bonus away. The event's self value is [frame + 0x50]. ===== */
static RValue *hook_m_su0268_diminish(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(M_DIMINISH);
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    int *flag = (int *)RVA(M_WIGHT_FLAG);
    *flag = 0;
    if (argc == 2 && args && args[0] && args[1]) {
        RValue cr = e_var((RValue *)(frame + 0x50), E_CREATURE_VAR), id, *pid = &id;
        int enemy = e_is_enemy(&cr), ok1, ok2, ok3;
        m_real(&id, 1515.0);                                              /* Master of Wights */
        if (e_call(enemy ? E_ANY_ENEMY : E_ANY_ALLY, self, other, 1, &pid) && m_race_is(&cr, M_WIGHT_STR)) {
            RValue hp = e_var(&cr, M_HPMAX_VAR), na, np, *a[2];
            double h = b2_num(&hp, &ok1), am = b2_num(args[0], &ok2), pool = b2_num(args[1], &ok3);
            if (ok1 && ok2 && ok3 && h > 0) {
                m_real(&na, h);
                m_real(&np, am > 0 ? pool * h / am : pool);
                a[0] = &na; a[1] = &np;
                *flag = 1;
                return orig(self, other, ret, 2, a);
            }
        }
    }
    return orig(self, other, ret, argc, args);
}
static char hook_m_su0268_race(RValue *a, RValue *b)
{
    int *flag = (int *)RVA(M_WIGHT_FLAG);
    if (*flag) { *flag = 0; return 0; }
    return ((MCmp2)RVA(M_EQ))(a, b);
}

/* ===== SU-0200 Disarmed: "Disarmed creatures lose the benefits from their equipped Artifact, other than Health."
 * (1) scr_CritHasPassive L60 reads creature.artifact before the Artifact trait (L62) and Nether Stone traits (L66-L69):
 *     stand in for that read and report "no artifact" (-1) while the creature is Disarmed (condition 31), so both
 *     checks are skipped as for a creature without an Artifact. The creature is the read's own instance argument.
 * (2) inv_ArtifactStatTotal L41 adds the Nether Stone's value of the property: 0 for a non-stat property (tricks:
 *     dodge, crit, ...) while the Artifact's owner is Disarmed, mirroring inv_ArtifactGetStat's L12-L17 rule for the
 *     Artifact's own slots (stat ids 0-4 and 54-63 are already dropped by the stat getters; Health stays). ===== */
static void *hook_m_su0200_artifact(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    void *r = ((VarGet)RVA(0x1478bbd70))(inst, var_id, index, out, a5, a6);
    int ok = 0;
    double v = out ? b2_num(out, &ok) : 0.0;
    if (out && ok && v != -1.0) {
        void *self = *(void **)RVA(M_CUR_SELF);
        if (m_has_condition(self, self, inst, 31.0)) m_real(out, -1.0);
    }
    return r;
}

static int m_is_stat_property(double p)
{
    return (p >= 0 && p <= 4 && p == (int)p) || (p >= 54 && p <= 63 && p == (int)p);
}

static RValue *hook_m_su0200_nether(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(M_NETHER_STAT);
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue *item = (RValue *)(frame + 0x70);                             /* inv_ArtifactStatTotal's item */
    int ok = 0;
    double p = (argc >= 2 && args && args[1]) ? b2_num(args[1], &ok) : 0.0;
    if (argc >= 2 && args && args[1] && ok && !m_is_stat_property(p)) {
        RValue o, ex, *po, *pe, *a[1];
        int disarmed = 0;
        memset(&o, 0, sizeof o); memset(&ex, 0, sizeof ex);
        a[0] = item;
        po = ((GmlScript)RVA(M_ART_OWNER))(self, other, &o, 1, a);
        if (!po) po = &o;
        if (((CmpInt)RVA(0x14028ca10))(po, -1)) {                          /* owner > -1 */
            a[0] = po;
            pe = ((MCallBuiltin)RVA(M_CALL_BUILTIN))(self, other, &ex, 1, *(int *)RVA(M_INSTANCE_EXISTS_ID), a);
            if (e_truthy(pe, &ex)) disarmed = m_has_condition(self, other, po, 31.0);
            ((MRelease)RVA(M_RELEASE))(&ex);
        }
        ((MRelease)RVA(M_RELEASE))(&o);
        if (disarmed) { m_real(ret, 0.0); return ret; }
    }
    return orig(self, other, ret, argc, args);
}

/* ===== SU-0280 Improbable Catapult: "enemies gain a copy of its innate trait". These Avatar traits asked only your
 * side (`slot > 0 && scr_AnyAllyHasPassive(id)`, The End `slot == 0 && ...`), so an enemy copy did nothing. The slot
 * tests are dropped (byte edits) and every call site below stands in for scr_AnyAllyHasPassive: the side asked is the
 * subject's own side (mode 0: the creature that attacks / casts / takes the damage / owns the Nether Stone) or the
 * opposite one (mode 1: The End, "at the end of each enemy's turn"). Sites are told apart by the return address.
 * The Black (mode 2 / 3) has no subject: "Enemies always have ..." runs its block for your holder and, when the enemy
 * side holds it too, a second time for the enemy holder (the block-end cave stub jumps back to L564).
 * I HATE YOU (610) is fixed by SU-0178. Brothel and Perfect Imperfection's Timewalk grant run at the start of battle,
 * before any copy exists, so they are not part of this. ===== */
typedef struct { unsigned ret_rva; unsigned off; unsigned char ptr, mode; } MAvSite;
#define M_RET(va) ((unsigned)((va) + 5 - 0x140000000ULL))
static const MAvSite m_av_sites[] = {
    { M_RET(0x1406e7766), 0x68,    0, 0 },   /* Firelord (bc_CreatureAttack, attacker) */
    { M_RET(0x140e1cca2), 0x21fd8, 0, 0 },   /* Prayer Position, damage taken (bc_EventDamage, creature) */
    { M_RET(0x140b07d59), 0x48,    1, 0 },   /* Prayer Position, Defend at end of turn (creatureturn) */
    { M_RET(0x140e969e1), 0x21fd8, 0, 0 },   /* Avenged Sevenfold (bc_EventDamage, creature) */
    { M_RET(0x1415aff0c), 0xb728,  0, 0 },   /* Expanded Power (bc_SpellDamage, caster) */
    { M_RET(0x140b06b36), 0x48,    1, 1 },   /* The End gate (creatureturn's enemies) */
    { M_RET(0x140b0710b), 0x48,    1, 1 },   /* The End: the holder that deals the damage */
    { M_RET(0x140b0729f), 0x48,    1, 1 },   /* The End: the holder whose highest stat is used */
    { M_RET(0x140e19b0a), 0x21fd8, 0, 0 },   /* Perfect Imperfection, damage taken (creature) */
    { M_RET(0x140ea4fec), 0x21fc8, 0, 0 },   /* Perfect Imperfection, damage dealt (source) */
    { M_RET(0x14145c615), 0x88,    0, 0 },   /* The Truth, Nether Stone spell on cast (bc_OnCast) */
    { M_RET(0x141536bb8), 0x88,    0, 0 },   /* The Truth, on defend (bc_OnDefend) */
    { M_RET(0x14156b960), 0x88,    0, 0 },   /* The Truth, on provoke (bc_OnProvoke) */
    { M_RET(0x140c5ddd9), 0xba58,  1, 0 },   /* The Truth, start of turn (creatureturn) */
    { M_RET(0x1413b100e), 0x168f0, 0, 0 },   /* The Truth, on attack (bc_OnAttack, attacker) */
    { M_RET(0x141d9a829), 0x120,   0, 0 },   /* The Truth, Nether Stone power (inv_NetherStoneGetStat, owner) */
    { M_RET(0x1412b8c50), 0,       0, 2 },   /* The Black gate (bc_MaintainPermanentEffects L562) */
    { M_RET(0x1412b8cf5), 0,       0, 3 },   /* The Black holder (L564) */
};

static RValue *hook_m_su0280_any_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript ally = (GmlScript)RVA(M_ANY_ALLY), enemy = (GmlScript)RVA(M_ANY_ENEMY);
    unsigned rva = (unsigned)((BYTE *)_ReturnAddress() - g_base);
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    const MAvSite *s = 0;
    BYTE *pass = RVA(M_BLACK_PASS), *more = RVA(M_BLACK_MORE);
    int k;

    for (k = 0; k < (int)(sizeof m_av_sites / sizeof m_av_sites[0]); k++)
        if (m_av_sites[k].ret_rva == rva) { s = &m_av_sites[k]; break; }
    if (!s) return ally(self, other, ret, argc, args);

    if (s->mode == 2) {                                                  /* The Black gate */
        RValue *r = ally(self, other, ret, argc, args);
        *pass = 0; *more = 0;
        if (e_truthy(r, ret)) {
            RValue tmp, *r2;
            memset(&tmp, 0, sizeof tmp);
            r2 = enemy(self, other, &tmp, argc, args);
            *more = e_truthy(r2, &tmp) ? 1 : 0;
            ((MRelease)RVA(M_RELEASE))(&tmp);
            return r;
        }
        r = enemy(self, other, ret, argc, args);
        if (e_truthy(r, ret)) *pass = 1;
        return r;
    }
    if (s->mode == 3)                                                    /* The Black holder */
        return (*pass ? enemy : ally)(self, other, ret, argc, args);

    {
        RValue *subj = s->ptr ? *(RValue **)(frame + s->off) : (RValue *)(frame + s->off);
        int want_enemy;
        if (!subj) return ally(self, other, ret, argc, args);
        want_enemy = e_is_enemy(subj) ^ (s->mode == 1);
        return (want_enemy ? enemy : ally)(self, other, ret, argc, args);
    }
}
