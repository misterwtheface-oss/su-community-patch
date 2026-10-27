/* Hook batch K (errata round 2: battle start, timeline, event execution). Built by research/build_hooks_K.py
 * (research/hooks_K.json); included by hooks.c. Game addresses are 2.0.38 VAs rebased with RVA(). Every hook keeps the
 * exact signature of the callee it stands in for and falls back to the original behaviour when anything is
 * unexpected. Our data lives in 0x149ed89d0-0x149ed8a4f. */

#define K_SLOT_218      0x149ed8a00     /* hook pointer of SU-0218 (non-zero only while that fix is applied) */
#define K_MISERY        0x149ed8a08     /* byte: SU-0206 refusal armed (read by the L48 cave stub) */

#define K_ADD_CONDITION 0x142015940     /* scr_CritAddCondition(creature, condition, duration, ...) */
#define K_REALM_PROP    0x146639f60     /* scr_RealmHasProperty(id) */
#define K_IS_BUFF       0x141fa4c50     /* scr_ConditionIsBuff(condition) */
#define K_IS_DEBUFF     0x141fa5120     /* scr_ConditionIsDebuff(condition) */
#define K_IS_MINION     0x141fa5610     /* scr_ConditionIsMinion(condition) */
#define K_HAS_COND      0x14202b010     /* scr_CritHasCondition(creature, condition) */
#define K_PERK_LEVEL    0x1464eb110     /* scr_PerkLevel(perk, side) */
#define K_ANY_ENEMY     0x141f0b2d0     /* scr_AnyEnemyHasPassive(id) */
#define K_ALLIES_OF     0x14113fb50     /* bc_GetAlliesOf(creature, false, false): [0] = count, [1..n] */
#define K_EVENT_BUFF    0x140ccac40     /* bc_EventBuff(source, creature, condition, duration, -1, -1, -1, last, text) */
#define K_ADD_EVENT     0x141ef3830     /* scr_AddEventToStack(mode, event) */
#define K_LCZ           0x141dc5060     /* lcz(key) */

#define K_VARGET        0x1478bbd70
#define K_VARSET        0x1478bc260
#define K_GLOBAL_REF    0x140297c10     /* (global object, var id) -> the global variable's value */
#define K_GLOBAL_OBJ    0x1499f57c8
#define K_EQ_INT        0x14028c8f0
#define K_GT_INT        0x14028ca10
#define K_LE_INT        0x1402bd5d0
#define K_EQ            0x14028c8d0     /* value == value */
#define K_TO_BOOL       0x147871cf0
#define K_FREE          0x14028c220     /* release a value (no-op for plain kinds) */
#define K_COPY          0x14028c360     /* construct a copy (fresh destination) */
#define K_ASSIGN        0x14028c410     /* dst = src (releases dst first) */
#define K_ARR_GET       0x14028c820     /* element pointer of an array value */
#define K_CONCAT        0x1402908a0     /* out = a + b (strings) */
#define K_INT_SET       0x14028c530     /* v = int (as a real) */
#define K_IRANDOM       0x1478b83e0     /* irandom_range(lo, hi) on 64-bit ints, the game's RNG */

/* variable id slots */
#define K_V_SLOT        0x1499e0aa8
#define K_V_CRITCONST   0x1499e0738
#define K_V_HERBWATER   0x1499e1648
#define K_V_CANRES      0x1499e1ce8
#define K_V_NEMESIS     0x1499e0d78     /* global.nemesis */
#define K_V_BATTLETYPE  0x1499e0a98     /* global.battletype */
#define K_S_WONDER      0x149d661d0     /* string globals: "L_P_FORSAKENWONDER", "(", ")" */
#define K_S_OPEN        0x149d66010
#define K_S_CLOSE       0x149d66250

typedef RValue *(*KGlobalRef)(void *global_obj, int var_id);
typedef void *(*KVarSet)(RValue *inst, int var_id, int index, RValue *value, int a5, int a6);
typedef char (*KCmp)(RValue *a, RValue *b);
typedef void (*KFree)(RValue *v);
typedef RValue *(*KCopy)(RValue *dst, RValue *src);
typedef RValue *(*KArrGet)(RValue *arr, int i);
typedef RValue *(*KConcat)(RValue *out, RValue *a, RValue *b);
typedef RValue *(*KIntSet)(RValue *v, int n);
typedef double (*KIRandom)(long long lo, long long hi);

#define K_CALLER_RSP ((char *)_AddressOfReturnAddress() + 8)

static void k_real(RValue *v, double x) { memset(v, 0, sizeof *v); v->v.real = x; }
static void k_bool(RValue *v, int b) { memset(v, 0, sizeof *v); v->v.real = b ? 1.0 : 0.0; v->kind = 13; }
static void k_free(RValue *v) { ((KFree)RVA(K_FREE))(v); }

/* Numeric value of an RValue: real 0, int32 7, int64 10, bool 13; ok = 0 for anything else. */
static double k_num(const RValue *v, int *ok)
{
    *ok = 1;
    switch (v->kind & 0xffffff) {
    case 0: case 13: return v->v.real;
    case 7: return (double)(int)v->v.i64;
    case 10: return (double)v->v.i64;
    }
    *ok = 0;
    return 0.0;
}

static RValue k_var(RValue *inst, unsigned long long slot_va)
{
    RValue out;
    memset(&out, 0, sizeof out);
    ((VarGet)RVA(K_VARGET))(inst, *(int *)RVA(slot_va), (int)0x80000000, &out, 0, 0);
    return out;
}

static RValue *k_global(unsigned long long slot_va)
{
    return ((KGlobalRef)RVA(K_GLOBAL_REF))(*(void **)RVA(K_GLOBAL_OBJ), *(int *)RVA(slot_va));
}

static int k_eq_int(RValue *v, int n) { return v && ((CmpEqInt)RVA(K_EQ_INT))(v, n) != 0; }

/* creature.slot > 0 (your side); 0 when the value has no usable slot */
static int k_yours(RValue *c)
{
    RValue s = k_var(c, K_V_SLOT);
    int r = ((CmpInt)RVA(K_GT_INT))(&s, 0) != 0;
    k_free(&s);
    return r;
}

static int k_var_is(RValue *c, unsigned long long slot_va, int n)
{
    RValue x = k_var(c, slot_va);
    int r = k_eq_int(&x, n);
    k_free(&x);
    return r;
}

/* Call a GML script; returns its truthiness and releases the result. */
static int k_call(unsigned long long fn, void *self, void *other, int argc, RValue **argv)
{
    RValue res, *r;
    int b;
    memset(&res, 0, sizeof res);
    r = ((GmlScript)RVA(fn))(self, other, &res, argc, argv);
    b = ((ToBool)RVA(K_TO_BOOL))(r ? r : &res) != 0;
    k_free(&res);
    return b;
}

static int k_call1(unsigned long long fn, void *self, void *other, RValue *a0)
{
    RValue *a[1];
    a[0] = a0;
    return k_call(fn, self, other, 1, a);
}

/* scr_PerkLevel(perk, side) > 0; side < 0 passes undefined (the in-battle Photosynthesis / Fertility form) */
static int k_perk(void *self, void *other, double perk, double side)
{
    RValue p, s, *a[2];
    k_real(&p, perk);
    if (side < 0) memcpy(&s, RVA(0x1498e0f50), sizeof s); else k_real(&s, side);   /* static undefined */
    a[0] = &p; a[1] = &s;
    return k_call(K_PERK_LEVEL, self, other, 2, a);
}

static int k_has_cond(void *self, void *other, RValue *c, RValue *cond)
{
    RValue *a[2];
    a[0] = c; a[1] = cond;
    return k_call(K_HAS_COND, self, other, 2, a);
}

/* ===== SU-0218 Photosynthesis: "Your Herbling has 3% more stats ... for each time it has received ... buffs or
 * minions ... in battle." In battle bc_OnBuffDebuff (buffs) and bc_OnMinion (minions) do, for your Herbling
 * (critconstant 970) with perk 325: herbwater += 3, then += 1.5 with Fertility (perk 455). Start-of-battle grants are
 * direct scr_CritAddCondition calls with no event, so they never counted. Applied after a direct add in
 * bc_StartupBuffsDebuffs when the Herbling holds the condition afterwards (a refused add does not count). */
static void k_herb_count(void *self, void *other, RValue *c, RValue *cond)
{
    RValue hw;
    int ok;
    double x;
    if (!k_var_is(c, K_V_CRITCONST, 970)) return;
    if (!k_call1(K_IS_BUFF, self, other, cond) && !k_call1(K_IS_MINION, self, other, cond)) return;
    if (!k_perk(self, other, 325.0, -1.0) || !k_yours(c)) return;
    if (!k_has_cond(self, other, c, cond)) return;
    hw = k_var(c, K_V_HERBWATER);
    x = k_num(&hw, &ok);
    k_free(&hw);
    if (!ok) return;
    x += 3.0;
    if (k_perk(self, other, 455.0, -1.0)) x += 1.5;
    k_real(&hw, x);
    ((KVarSet)RVA(K_VARSET))(c, *(int *)RVA(K_V_HERBWATER), (int)0x80000000, &hw, 0, 0);
}

static RValue *hook_k_su0218_add(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(K_ADD_CONDITION))(self, other, ret, argc, args);
    if (argc >= 2 && args && args[0] && args[1]) k_herb_count(self, other, args[0], args[1]);
    return r;
}

/* ===== SU-0216 Forsaken Wonder: "Buffs granted by your creatures' Relics last forever. In addition, after your Relics
 * give one of your creatures a buff, they grant all your other creatures that buff as well." The spread (bc_OnBuffDebuff
 * L57-L66) and the permanence (scr_CritAddCondition's Wonder block, SU-0080) only see buff events; the start-of-battle
 * Relic buffs and Bloodseeker's 'always has' buffs are direct adds. These hooks stand in for those adds:
 *   - permanence: with Forsaken Wonder (655) a Relic buff on your creature gets duration -2 (forever), and with
 *     Primordial Curse (654) so does Blazefury 40's start-of-battle Burning (the in-battle rule, SU-0080 v3, sets no
 *     side limit); 'always has' adds already pass -2;
 *   - spread: when the bearer really holds the buff afterwards, the same events the in-battle spread queues:
 *     bc_EventBuff(-1, ally, buff, -2, -1, -1, -1, last, "(" + lcz("L_P_FORSAKENWONDER") + ")") and
 *     scr_AddEventToStack(1, event) for every creature of bc_GetAlliesOf(bearer, false, false). Source -1, as in the
 *     game, so the copies don't spread again; duration -2 as SU-0080 v4 gives the in-battle copies. The controller runs
 *     these events before the next start-of-battle phase. Under Misery (SU-0206) the bearer's add is refused, so
 *     nothing spreads; the copies are buff events, which Misery refuses on its own. */
static void k_spread(void *self, void *other, RValue *bearer, RValue *cond)
{
    RValue f0, f1, res, allies, key, name, open_, close_, c1, text, *r, *e, *ga[3], *la[1];
    int ok, i, n;
    double cnt;

    k_bool(&f0, 0); k_bool(&f1, 0); memset(&res, 0, sizeof res); memset(&allies, 0, sizeof allies);
    ga[0] = bearer; ga[1] = &f0; ga[2] = &f1;
    r = ((GmlScript)RVA(K_ALLIES_OF))(self, other, &res, 3, ga);
    ((KCopy)RVA(K_ASSIGN))(&allies, r ? r : &res);
    k_free(&res);
    e = ((KArrGet)RVA(K_ARR_GET))(&allies, 0);
    cnt = e ? k_num(e, &ok) : (ok = 0, 0.0);
    n = ok ? (int)cnt : 0;
    if (n <= 0 || n > 64) { k_free(&allies); return; }

    /* the in-battle spread's text: "(" + lcz("L_P_FORSAKENWONDER") + ")" */
    memset(&key, 0, sizeof key); memset(&name, 0, sizeof name); memset(&open_, 0, sizeof open_);
    memset(&close_, 0, sizeof close_); memset(&c1, 0, sizeof c1); memset(&text, 0, sizeof text);
    ((KCopy)RVA(K_COPY))(&key, (RValue *)RVA(K_S_WONDER));
    ((KCopy)RVA(K_COPY))(&open_, (RValue *)RVA(K_S_OPEN));
    ((KCopy)RVA(K_COPY))(&close_, (RValue *)RVA(K_S_CLOSE));
    la[0] = &key;
    r = ((GmlScript)RVA(K_LCZ))(self, other, &name, 1, la);
    r = ((KConcat)RVA(K_CONCAT))(&c1, &open_, r ? r : &name);
    r = ((KConcat)RVA(K_CONCAT))(&text, r ? r : &c1, &close_);

    for (i = 1; i <= n; i++) {
        RValue src, ally, dur, m1, m2, m3, last, ev, mode, out, *ba[9], *aa[2], *er;
        e = ((KArrGet)RVA(K_ARR_GET))(&allies, i);
        if (!e) break;
        memset(&ally, 0, sizeof ally);
        ((KCopy)RVA(K_ASSIGN))(&ally, e);
        k_real(&src, -1.0); k_real(&dur, -2.0); k_real(&m1, -1.0); k_real(&m2, -1.0); k_real(&m3, -1.0);
        k_bool(&last, i == n);
        ba[0] = &src; ba[1] = &ally; ba[2] = cond; ba[3] = &dur; ba[4] = &m1; ba[5] = &m2; ba[6] = &m3;
        ba[7] = &last; ba[8] = r ? r : &text;
        memset(&ev, 0, sizeof ev);
        er = ((GmlScript)RVA(K_EVENT_BUFF))(self, other, &ev, 9, ba);
        k_real(&mode, 1.0); memset(&out, 0, sizeof out);
        aa[0] = &mode; aa[1] = er ? er : &ev;
        ((GmlScript)RVA(K_ADD_EVENT))(self, other, &out, 2, aa);
        k_free(&out); k_free(&ev); k_free(&ally);
    }
    k_free(&text); k_free(&c1); k_free(&name); k_free(&key); k_free(&open_); k_free(&close_); k_free(&allies);
}

static RValue *k_relic_add(int start, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *a[8], dur, *r;
    int perm = 0, buff = 0, k;
    RValue **use = args;
    if (argc < 3 || argc > 8 || !args || !args[0] || !args[1] || !args[2] || !k_yours(args[0]))
        return ((GmlScript)RVA(K_ADD_CONDITION))(self, other, ret, argc, args);
    buff = k_call1(K_IS_BUFF, self, other, args[1]) && !k_call1(K_IS_MINION, self, other, args[1]);
    if (buff && k_perk(self, other, 655.0, 1.0)) perm = 655;
    else if (start && !buff && k_call1(K_IS_DEBUFF, self, other, args[1]) && k_perk(self, other, 654.0, 1.0)) perm = 654;
    if (perm && !k_eq_int(args[2], -2)) {
        for (k = 0; k < argc; k++) a[k] = args[k];
        k_real(&dur, -2.0);
        a[2] = &dur;
        use = a;
    }
    r = ((GmlScript)RVA(K_ADD_CONDITION))(self, other, ret, argc, use);
    if (perm == 655 && k_has_cond(self, other, args[0], args[1])) k_spread(self, other, args[0], args[1]);
    if (start && *(void **)RVA(K_SLOT_218)) k_herb_count(self, other, args[0], args[1]);   /* SU-0218 on */
    return r;
}

/* bc_StartupBuffsDebuffs: the Relic rank 10 / 50 start-of-battle buffs and Blazefury 40 */
static RValue *hook_k_su0216_start(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return k_relic_add(1, self, other, ret, argc, args); }

/* bc_MaintainPermanentEffects: Bloodseeker 30 / 60 'always has' (re-added only when missing, so each spread follows a
 * real gain) */
static RValue *hook_k_su0216_always(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return k_relic_add(0, self, other, ret, argc, args); }

/* ===== SU-0206 Misery (Nemesis): "Your creatures cannot gain buffs or stats." The game refuses only buff events
 * (bc_EventBuff L111-L113: global.nemesis == 2 && creature.slot > 0). scr_CritAddCondition's L46 gate is reached
 * exactly for a buff on your creature (slot > 0 && scr_ConditionIsBuff) and asks scr_RealmHasProperty(31) (realm
 * 'Maximum Buffs'); its refusal exit is L51. Stands in for that call: under Misery (and not a minion) it answers true
 * and arms the cave stub at L48, which jumps to the game's own L51 exit (the add is refused, like a full realm buff
 * cap). Otherwise the original call. Condition local: [rbp - 0x38] = caller rsp + 0xc8. */
static RValue *hook_k_su0206_realm_prop(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    BYTE *flag = RVA(K_MISERY);
    RValue *nem, *cond = (RValue *)(K_CALLER_RSP + 0xc8);
    *flag = 0;
    if (argc == 1 && args && args[0] && k_eq_int(args[0], 31)) {
        nem = k_global(K_V_NEMESIS);
        if (nem && k_eq_int(nem, 2) && !k_call1(K_IS_MINION, self, other, cond)) {
            *flag = 1;
            k_real(ret, 1.0);
            return ret;
        }
    }
    return ((GmlScript)RVA(K_REALM_PROP))(self, other, ret, argc, args);
}

/* ===== SU-0183 Hymn of Panic: "At the start of battle, the Timeline is shuffled randomly." bc_CreateCreatureList
 * L194-L200 gave each creature a coin flip between two fixed sort keys (1 / 1999999999999098), so the order inside each
 * group was whatever the sort left for ties. Stands in for both key setters: a uniform random key in [2, 1e15 + 2)
 * from the game's RNG (exact as a real), so every order is equally likely; still below the explicit 'start at the top'
 * keys set later. */
static RValue *hook_k_su0183_key(RValue *v, long long n)
{
    double x;
    (void)n;
    ((KIntSet)RVA(K_INT_SET))(v, 0);                         /* releases the old value, makes it a real */
    x = ((KIRandom)RVA(K_IRANDOM))(0, 999999999999999LL);
    v->v.real = 2.0 + x;
    return v;
}

/* ===== SU-0189 "When a boss would be forced to move to the bottom of the Timeline, they are instead moved down 1
 * position only." bc_ExecuteEvents L1053 lists battle types 38, 39, 36, 88; Lord Zantai's (37), a boss fight everywhere
 * else (instant kills), is missing. Stands in for the last compare (== 88): true for 88 or 37. */
static char hook_k_su0189_boss_type(RValue *v, int n)
{
    if (((CmpEqInt)RVA(K_EQ_INT))(v, n)) return 1;
    return (char)(n == 88 && ((CmpEqInt)RVA(K_EQ_INT))(v, 37) != 0);
}

/* ===== SU-0310 "it cannot be resurrected" (can_resurrect = false, set at the death by Burn Their Corpses, Endwalker,
 * Feast and Famine, End On a High Note, Epigraphy, Disintegrating Arrow). bc_EventResurrect checks the flag when the
 * resurrection is queued; Terminus, Defy the Gods, Reincarnation and Genesis queue it before the death, so the first
 * cycle came back. Stands in for the execute-time `creature.hp <= 0` test (bc_ExecuteEvents L1312): also false when
 * can_resurrect == false, except bc_EventResurrect's own exemptions (an enemy in a False God battle; Vulcanar with
 * Ultimate Ember in play). False skips the case as when Health > 0. Event creature at [caller rsp + 0x9968],
 * bc_ExecuteEvents' self / other at [caller rsp + 0xf8c0 / 0xf8c8]. */
static char hook_k_su0310_dead(RValue *v, int n)
{
    char *frame = K_CALLER_RSP;
    RValue *c = (RValue *)(frame + 0x9968);
    void *self = *(void **)(frame + 0xf8c0), *other = *(void **)(frame + 0xf8c8);
    RValue can, no, *bt;
    char dead = ((CmpInt)RVA(K_LE_INT))(v, n);
    int blocked;
    if (!dead || n != 0) return dead;
    can = k_var(c, K_V_CANRES);
    k_bool(&no, 0);
    blocked = ((KCmp)RVA(K_EQ))(&can, &no) != 0;            /* the game's own test: can_resurrect == false */
    k_free(&can);
    if (!blocked) return dead;
    if (!k_yours(c)) {                                       /* enemy: the queue-time exemptions */
        bt = k_global(K_V_BATTLETYPE);
        if (bt && k_eq_int(bt, 88)) return dead;
        if (k_var_is(c, K_V_CRITCONST, 736)) {
            RValue id;
            k_real(&id, 678.0);
            if (k_call1(K_ANY_ENEMY, self, other, &id)) return dead;
        }
    }
    return 0;
}
