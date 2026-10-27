/* Hook batch J (errata round 2: stats, stat getters, race counts). Built by research/build_hooks_J.py
 * (research/hooks_J.json); included by hooks.c. Game addresses are 2.0.38 VAs, rebased with RVA(). Every hook keeps
 * the exact signature of the callee it stands in for and falls back to the original behaviour when anything is
 * unexpected. Our state lives in the data range 0x149ed8950-0x149ed89cf; the frame offsets below are checked against
 * the exe by the builder.
 *
 *   SU-0281 Jealousy            crit_attack / _defense / _intelligence / _speed: the "Imler count == 1" and
 *                               "Imling count == 1" tests read the shared race counter (bc_CountRace)
 *   SU-0261 Devotion            the same two tests in bc_EventDamage
 *   SU-0264 Draconic Arrogance  the allies' highest stat is read from their stored stats (no getter recursion)
 *   SU-0269 Fallen Star         a Feared holder does not steal; Max Health gains can be stolen too
 *   SU-0202 Unstable Horror     the master's highest stat may be Health (Maximum Health is used)
 *   SU-0275 Grandiose           raw buff / debuff list counts read the shared counters (bc_CountBuffs / bc_CountDebuffs)
 */

#define J_SELF        0x149ed8950   /* qword: self of the getter whose race test is running (set by the cave stub) */
#define J_OTHER       0x149ed8958   /* qword: other */
#define J_IDX         0x149ed8960   /* byte: which getter (0 attack, 1 defense, 2 intelligence, 3 speed) */

#define J_VARGET      0x1478bbd70
#define J_VARSET      0x1478bc260   /* (inst, var id, index | 0x80000000, value) */
#define J_ASSIGN      0x14028c410   /* dst = src (reference counted copy) */
#define J_FREE        0x14028c220   /* release a temporary value */
#define J_EQ          0x14028c8d0   /* value == value */
#define J_EQ_INT      0x14028c8f0   /* value == int */
#define J_SET_INT     0x14028c530   /* dst = (real) int; returns dst */
#define J_CONCAT      0x1402908a0   /* out = a + b; returns out */
#define J_WRAP_GLOBAL 0x140297c20   /* value wrapping the global object */
#define J_GLOBAL_OBJ  0x1499f57c8
#define J_TO_BOOL     0x147871cf0

#define J_COUNT_RACE   0x14068f7b0  /* bc_CountRace(list, race) */
#define J_COUNT_BUFFS  0x140689e20  /* bc_CountBuffs(creature) */
#define J_COUNT_DEBUFS 0x14068d0c0  /* bc_CountDebuffs(creature) */
#define J_GET_BUFFS    0x1411422e0  /* bc_GetCreatureBuffs(creature) */
#define J_GET_DEBUFS   0x141142ab0  /* bc_GetCreatureDebuffs(creature) */
#define J_NTH_AMT      0x14612aad0  /* scr_GetCritNthHighestStatAmt(creature, n, base) */
#define J_HAS_PASSIVE  0x14202c2c0  /* scr_CritHasPassive(creature, id) */
#define J_HAS_COND     0x14202b010  /* scr_CritHasCondition(creature, condition) */
#define J_ROLL         0x146666e40  /* scr_Roll(chance) */
#define J_ENEMIES_OF   0x141161660  /* bc_GetEnemiesOf */
#define J_LCZ          0x141dc5060  /* localized text of a key */
#define J_FLOATING     0x140fe96c0  /* bc_EventFloating(text, color, creature, flag) */
#define J_ADD_EVENT    0x141ef3830  /* scr_AddEventToStack(mode, event) */

/* variable id slots */
#define J_V_SLOT       0x1499e0aa8
#define J_V_CREATURE   0x1499e3228
#define J_V_CRITLIST   0x1499e09f8  /* creatureList (global): [0] = count, [1..] = the timeline */
#define J_V_HPMAX      0x1499e0b68
#define J_V_R_ATTACK   0x149930148  /* recent_attack ... the getters' stored results */
#define J_V_R_DEFENSE  0x1499304a8
#define J_V_R_INT      0x149930138
#define J_V_R_SPEED    0x1499302b8

typedef char (*JEqInt)(RValue *v, int n);
typedef char (*JEq)(RValue *a, RValue *b);
typedef void (*JFree)(RValue *v);
typedef void (*JAssign)(RValue *dst, RValue *src);
typedef RValue *(*JSetInt)(RValue *dst, int n);
typedef RValue *(*JConcat)(RValue *out, RValue *a, RValue *b);
typedef void *(*JWrapGlobal)(RValue *out, void *global_obj);
typedef void *(*JVarSet)(RValue *inst, int var_id, int index, RValue *value);

static void j_undef(RValue *v) { memset(v, 0, sizeof *v); v->kind = 5; }
static void j_real(RValue *v, double x) { memset(v, 0, sizeof *v); v->v.real = x; }

/* real 0, int32 7, int64 10, bool 13 */
static double j_num(const RValue *v, int *ok)
{
    unsigned k = v->kind & 0xffffff;
    *ok = 1;
    if (k == 0 || k == 13) return v->v.real;
    if (k == 7) return (double)(int)v->v.i64;
    if (k == 10) return (double)v->v.i64;
    *ok = 0;
    return 0.0;
}

static void j_get(RValue *inst, unsigned long long slot_va, int index, RValue *out)
{
    j_undef(out);
    ((VarGet)RVA(J_VARGET))(inst, *(int *)RVA(slot_va), index, out, 0, 0);
}

static int j_truthy(RValue *v) { return ((ToBool)RVA(J_TO_BOOL))(v) != 0; }

/* Call a GML script; *num gets its numeric result. Returns 0 if the result is not a number. */
static int j_script_num(unsigned long long fn, void *self, void *other, int argc, RValue **args, double *num)
{
    RValue res, *r; int ok;
    j_undef(&res);
    r = ((GmlScript)RVA(fn))(self, other, &res, argc, args);
    *num = j_num(r ? r : &res, &ok);
    ((JFree)RVA(J_FREE))(&res);
    return ok;
}

static int j_script_bool(unsigned long long fn, void *self, void *other, int argc, RValue **args)
{
    RValue res, *r; int b;
    j_undef(&res);
    r = ((GmlScript)RVA(fn))(self, other, &res, argc, args);
    b = j_truthy(r ? r : &res);
    ((JFree)RVA(J_FREE))(&res);
    return b;
}

/* ===== SU-0281 Jealousy / SU-0261 Devotion: "If you only have one Imler and one Imling fighting on your side". The
 * code counts the race field of each ally itself, so Odd One, Shackler's Mastery and Forest Pact (which live only in
 * bc_CountRace) never reach it. These hooks stand in for the runtime "count == 1" compares of the two count locals
 * and compare bc_CountRace(allies, race) instead, on the same ally list. They work only once the holder was found in
 * that list (the third test), so the stat getters' hot path pays one bool read. */
typedef struct { int imler, imling, found, allies; unsigned long long s_imler, s_imling; } JRaceSite;

static char j_race_test(RValue *v, int n, char *base, const JRaceSite *t, void *self, void *other)
{
    JEqInt eq = (JEqInt)RVA(J_EQ_INT);
    RValue *race, *a[2];
    double cnt;
    if (v == (RValue *)(base + t->imler)) race = (RValue *)RVA(t->s_imler);
    else if (v == (RValue *)(base + t->imling)) race = (RValue *)RVA(t->s_imling);
    else return eq(v, n);
    if (!j_truthy((RValue *)(base + t->found))) return eq(v, n);
    a[0] = (RValue *)(base + t->allies); a[1] = race;
    if (!j_script_num(J_COUNT_RACE, self, other, 2, a, &cnt)) return eq(v, n);
    return cnt == (double)n;
}

/* crit_attack L577, crit_defense L630, crit_intelligence L673, crit_speed L636; offsets from rbp (= caller rsp + 0x100) */
static const JRaceSite j_jealousy[4] = {
    { 0x510, 0x500, 0x4f0, -0x38, 0x149d692a0, 0x149d69270 },
    { 0x4b0, 0x4a0, 0x490, -0x38, 0x149d69400, 0x149d69310 },
    { 0x500, 0x4f0, 0x4e0, -0x38, 0x149d69520, 0x149d694b0 },
    { 0x4a0, 0x490, 0x480, -0x38, 0x149d696a0, 0x149d695d0 },
};

static char hook_j_su0281_count(RValue *v, int n)
{
    void *self = *(void **)RVA(J_SELF), *other = *(void **)RVA(J_OTHER);   /* read first: the cave stub just set them */
    unsigned idx = *(BYTE *)RVA(J_IDX);
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    if (idx >= 4) return ((JEqInt)RVA(J_EQ_INT))(v, n);
    return j_race_test(v, n, frame + 0x100, &j_jealousy[idx], self, other);
}

/* bc_EventDamage L2777 (rsp-based frame; self / other in the home slots) */
static const JRaceSite j_devotion = { 0x22948, 0x22958, 0x22968, 0x22178, 0x149d610a0, 0x149d60f00 };

static char hook_j_su0261_count(RValue *v, int n)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    return j_race_test(v, n, frame, &j_devotion, *(void **)(frame + 0x30490), *(void **)(frame + 0x30498));
}

/* ===== SU-0264 Draconic Arrogance: "additional stats equal to 5% of your other creatures' highest stats". The game
 * asks scr_GetCritNthHighestStatAmt(ally, 1, false), which calls the ally's full crit_attack / _defense /
 * _intelligence / _speed; with From Death to Destiny or Lifeblood on the other side the two getters call each other
 * without end (crash). Stands in for those four calls and reads the ally's stored results instead (recent_attack,
 * recent_defense, recent_intelligence, recent_speed and Maximum Health: the same five values, as Embolden does). */
static RValue *hook_j_su0264_highest(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    static const unsigned long long vars[5] = { J_V_R_ATTACK, J_V_R_DEFENSE, J_V_R_INT, J_V_R_SPEED, J_V_HPMAX };
    double n, base, best = 0.0, x;
    int ok, i, any = 0;
    if (argc == 3 && args && args[0] && args[1] && args[2]) {
        n = j_num(args[1], &ok);
        if (ok && n == 1.0) {
            base = j_num(args[2], &ok);
            if (ok && base == 0.0) {
                for (i = 0; i < 5; i++) {
                    RValue v;
                    j_get(args[0], vars[i], (int)0x80000000, &v);
                    x = j_num(&v, &ok);
                    ((JFree)RVA(J_FREE))(&v);
                    if (!ok) { any = -1; break; }
                    if (!any || x > best) best = x;
                    any = 1;
                }
                if (any == 1) {
                    j_real(ret, best);
                    return ret;
                }
            }
        }
    }
    return ((GmlScript)RVA(J_NTH_AMT))(self, other, ret, argc, args);
}

/* ===== SU-0269 Fallen Star: "When an enemy would gain stats, this creature has a 50% chance to gain them instead."
 * Feared: "Fear creatures cannot gain stats". The Fear test runs before Fallen Star swaps the receiver, so a Feared
 * holder still gained. Stands in for the holder test scr_CritHasPassive(creatureList[i], 268) in the four stat gain
 * events: a Feared holder does not steal (the original creature keeps the gain). */
static int j_feared(void *self, void *other, RValue *who)
{
    RValue id, *a[2];
    j_real(&id, 32.0);                                   /* Feared */
    a[0] = who; a[1] = &id;
    return j_script_bool(J_HAS_COND, self, other, 2, a);
}

static RValue *hook_j_su0269_holder(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(J_HAS_PASSIVE))(self, other, ret, argc, args);
    if (argc >= 1 && args && args[0] && j_truthy(r ? r : ret) && j_feared(self, other, args[0])) {
        j_real(ret, 0.0);
        return ret;
    }
    return r;
}

/* slot: 0 = enemy side, > 0 = your side; -1 if unreadable */
static int j_side(RValue *c)
{
    RValue s; double x; int ok;
    j_get(c, J_V_SLOT, (int)0x80000000, &s);
    x = j_num(&s, &ok);
    ((JFree)RVA(J_FREE))(&s);
    if (!ok) return -1;
    return x == 0.0 ? 0 : (x > 0.0 ? 1 : -1);
}

/* The game's "Stolen" floater, as bc_EventGainAttack L311 builds it: L_B_STAT_GAIN_STOLEN + "\n" + "(" + Fallen Star
 * + ")", color 0xFFFF00, on the holder; queued with mode 1. */
static void j_stolen_floater(void *self, void *other, RValue *holder)
{
    JAssign assign = (JAssign)RVA(J_ASSIGN); JFree release = (JFree)RVA(J_FREE); JConcat cat = (JConcat)RVA(J_CONCAT);
    RValue k1, k2, l1, l2, nl, lp, rp, c1, c2, c3, c4, color, flag, fl, one, res, *a[4], *r1, *r2, *rf;
    j_real(&k1, 0); j_real(&k2, 0); j_real(&nl, 0); j_real(&lp, 0); j_real(&rp, 0);
    assign(&k1, (RValue *)RVA(0x149d615e0));             /* "L_B_STAT_GAIN_STOLEN" */
    assign(&k2, (RValue *)RVA(0x149d61500));             /* "L_TRAIT_NAME_FALLENSTAR" */
    assign(&nl, (RValue *)RVA(0x149d61660));             /* "\n" */
    assign(&lp, (RValue *)RVA(0x149d614f0));             /* "(" */
    assign(&rp, (RValue *)RVA(0x149d61400));             /* ")" */
    j_undef(&l1); j_undef(&l2);
    a[0] = &k1; r1 = ((GmlScript)RVA(J_LCZ))(self, other, &l1, 1, a);
    a[0] = &k2; r2 = ((GmlScript)RVA(J_LCZ))(self, other, &l2, 1, a);
    j_real(&c1, 0); j_real(&c2, 0); j_real(&c3, 0); j_real(&c4, 0);
    cat(&c1, r1 ? r1 : &l1, &nl);
    cat(&c2, &c1, &lp);
    cat(&c3, &c2, r2 ? r2 : &l2);
    cat(&c4, &c3, &rp);
    j_real(&color, 16776960.0);
    j_real(&flag, 1.0); flag.kind = 13;                   /* true */
    j_undef(&fl);
    a[0] = &c4; a[1] = &color; a[2] = holder; a[3] = &flag;
    rf = ((GmlScript)RVA(J_FLOATING))(self, other, &fl, 4, a);
    j_real(&one, 1.0); j_undef(&res);
    a[0] = &one; a[1] = rf ? rf : &fl;
    ((GmlScript)RVA(J_ADD_EVENT))(self, other, &res, 2, a);
    release(&res); release(&fl);
    release(&c4); release(&c3); release(&c2); release(&c1);
    release(&l2); release(&l1);
    release(&rp); release(&lp); release(&nl); release(&k2); release(&k1);
}

/* bc_EventGainMaxHP has no Fallen Star block. Stands in for its bc_GetEnemiesOf(event.creature, true) at L312 (the
 * Currents block, the place the other four gain events run Fallen Star) and first runs the same block: for each
 * timeline creature holding the trait (not Feared, see above) on the opposite side of the gaining creature, a 50%
 * roll; on success the floater and event.creature = the holder. Currents then sees the new receiver, as it does for
 * the other stats. The event value is the caller's [rsp + 0x50]. */
static RValue *hook_j_su0269_maxhp(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue *event = (RValue *)(frame + 0x50), g, cntv, holder, *a2[4], id;
    JFree release = (JFree)RVA(J_FREE);
    double cnt; int ok, i, stolen = 0, k;

    if (argc < 1 || argc > 4 || !args || !args[0])
        return ((GmlScript)RVA(J_ENEMIES_OF))(self, other, ret, argc, args);
    j_real(&g, 0);
    ((JWrapGlobal)RVA(J_WRAP_GLOBAL))(&g, *(void **)RVA(J_GLOBAL_OBJ));
    j_get(&g, J_V_CRITLIST, 0, &cntv);
    cnt = j_num(&cntv, &ok);
    release(&cntv);
    j_undef(&holder);
    for (i = 1; ok && i <= (int)cnt && i < 64; i++) {
        RValue h, cr, *a[2];
        int hs, cs, take = 0;
        j_get(&g, J_V_CRITLIST, i, &h);
        j_real(&id, 268.0); a[0] = &h; a[1] = &id;
        if (j_script_bool(J_HAS_PASSIVE, self, other, 2, a) && !j_feared(self, other, &h)) {
            j_get(event, J_V_CREATURE, (int)0x80000000, &cr);
            hs = j_side(&h); cs = j_side(&cr);
            if ((hs == 0 && cs == 1) || (hs == 1 && cs == 0)) {
                j_real(&id, 50.0); a[0] = &id;
                if (j_script_bool(J_ROLL, self, other, 1, a) && !((JEq)RVA(J_EQ))(&h, &cr)) take = 1;
            }
            release(&cr);
        }
        if (take) {
            j_stolen_floater(self, other, &h);
            ((JVarSet)RVA(J_VARSET))(event, *(int *)RVA(J_V_CREATURE), (int)0x80000000, &h);
            release(&holder);
            j_undef(&holder);
            ((JAssign)RVA(J_ASSIGN))(&holder, &h);
            stolen = 1;
        }
        release(&h);
    }
    release(&g);
    if (!stolen)
        return ((GmlScript)RVA(J_ENEMIES_OF))(self, other, ret, argc, args);
    a2[0] = &holder;
    for (k = 1; k < argc; k++) a2[k] = args[k];
    {
        RValue *r = ((GmlScript)RVA(J_ENEMIES_OF))(self, other, ret, argc, a2);
        release(&holder);
        return r;
    }
}

/* ===== SU-0202 Unstable Horror: "damage ... equal to 10% of its master's highest stat". The game re-picks the
 * second-highest stat when Health is highest (its stat switch has no Health case). The second pick now asks for the
 * highest again (constant edit), and this hook stands in for `amount = 0` right before the switch (bc_OnDefend L512,
 * bc_OnProvoke L165): when the stat is Health, amount = the master's Maximum Health (the value the highest-stat
 * ranking used for Health). Master at [rbp - 0x78], stat at [rbp + stat_off], rbp = caller rsp + 0x100. */
static RValue *j_unstable(char *frame, RValue *dst, int n, int stat_off, unsigned long long health_str)
{
    RValue *r = ((JSetInt)RVA(J_SET_INT))(dst, n);
    char *rbp = frame + 0x100;
    RValue hp; double x; int ok;
    if (n != 0 || !((JEq)RVA(J_EQ))((RValue *)(rbp + stat_off), (RValue *)RVA(health_str))) return r;
    j_get((RValue *)(rbp - 0x78), J_V_HPMAX, (int)0x80000000, &hp);
    x = j_num(&hp, &ok);
    ((JFree)RVA(J_FREE))(&hp);
    if (ok) j_real(dst, x);
    return r;
}

static RValue *hook_j_su0202_defend(RValue *dst, int n)
{ return j_unstable((char *)_AddressOfReturnAddress() + 8, dst, n, 0x2e0, 0x149d67500); }

static RValue *hook_j_su0202_provoke(RValue *dst, int n)
{ return j_unstable((char *)_AddressOfReturnAddress() + 8, dst, n, 0x290, 0x149d67bb0); }

/* ===== SU-0275 Grandiose: "your creatures act as if they have 3 more buffs, debuffs, and minions". The +3 (and
 * Redefined, perk 630) live only in bc_CountBuffs / bc_CountDebuffs; these effects fetch the raw list and read its
 * count (list[0]) instead: Lenience, Holy Might, Reckoning, Pandemonium Exploit, a +10% per buff spell; Under Stress,
 * Swell, Nighttaker, Ruin, Daybreaker, Heresy, a chance per debuff spell. Stands in for those list fetches only (the
 * builder checks that each site reads nothing but list[0]): the fresh list's count is replaced by the shared counter's
 * value. The list is the callee's new array (reference count 1); anything else is left alone. */
static RValue *j_list_count(unsigned long long fetch, unsigned long long counter,
                            void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(fetch))(self, other, ret, argc, args);
    RValue *arr = r ? r : ret, *d0;
    char *ref;
    double n; int ok;
    if (argc != 1 || !args || !args[0] || (arr->kind & 0xffffff) != 2 || !arr->v.ptr) return r;
    ref = (char *)arr->v.ptr;
    if (*(int *)(ref + 0x18) != 1 || *(int *)(ref + 0x24) < 1 || !*(RValue **)(ref + 8)) return r;
    d0 = *(RValue **)(ref + 8);
    j_num(d0, &ok);
    if (!ok || !j_script_num(counter, self, other, argc, args, &n)) return r;
    if (n < 0) n = 0;
    j_real(d0, n);
    return r;
}

static RValue *hook_j_su0275_buffs(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return j_list_count(J_GET_BUFFS, J_COUNT_BUFFS, self, other, ret, argc, args); }

static RValue *hook_j_su0275_debuffs(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return j_list_count(J_GET_DEBUFS, J_COUNT_DEBUFS, self, other, ret, argc, args); }
