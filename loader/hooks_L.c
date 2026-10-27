/* Hook batch L (errata round 2: spells, sealing, cards, luck; see research/build_hooks_L.py). Included by hooks.c.
 * Game addresses are 2.0.38 VAs rebased with RVA(). Hook slots live in the data range 0x149ed8a50-0x149ed8acf; the
 * trampolines (jmp [slot]) in the _RDATA slack 0x14a343d00-0x14a343fff. Every hook falls back to the original
 * behaviour when anything is unexpected. */

typedef void (*L_Free)(RValue *v);                                  /* 0x14028c220: release a value              */
typedef void (*L_Assign)(RValue *dst, RValue *src);                 /* 0x14028c410: dst = src (refcounted)       */
typedef void (*L_SetInt)(RValue *v, int n);                        /* 0x14028c530: v = n                        */
typedef int (*L_ToInt)(RValue *v);                                  /* 0x14028c580: value -> int (array index)   */
typedef char (*L_Eq)(RValue *a, RValue *b);                         /* 0x14028c8d0: a == b                       */
typedef char (*L_EqInt)(RValue *v, int n);                          /* 0x14028c8f0: v == n                       */
typedef char (*L_GtInt)(RValue *v, int n);                          /* 0x14028ca10: v > n                        */
typedef RValue *(*L_GlobalRef)(void *global_obj, int var_id);       /* 0x140297c10: a global variable's value    */
typedef void (*L_GlobalInst)(RValue *out, void *global_obj);        /* 0x140297c20: the global object as a value */

#define L_VAR(slot_va) (*(int *)RVA(slot_va))
#define L_NOIDX ((int)0x80000000)
#define L_CALLER_RSP ((char *)_AddressOfReturnAddress() + 8)
#define L_SLOT_ON(slot_va) (*(void **)RVA(slot_va) != 0)             /* a patch's hook slot is filled when it is on */

/* hook slots (must match research/build_hooks_L.py) */
#define L_SLOT_0289_READ  0x149ed8a50
#define L_SLOT_0289_STEP  0x149ed8a58
#define L_SLOT_0212_FLAG  0x149ed8a60
#define L_SLOT_0229_FLAG  0x149ed8a88
#define L_SLOT_0137       0x149ed8668                                /* SU-0137 (hooks_S.c) */

/* variable-id slots */
#define L_V_SEALED      0x1499e3348
#define L_V_SPELLID     0x1499e0b28
#define L_V_IS_ULTIMATE 0x1499354c8
#define L_V_SLOT        0x1499e0aa8
#define L_V_CRITS       0x1499e0668
#define L_V_CREATURE    0x1499e3228
#define L_V_AMOUNT      0x1499c91b8
#define L_V_TURN        0x1499e1f18                                  /* global creatureturn */
#define L_GLOBAL_OBJ    (*(void **)RVA(0x1499f57c8))

static void l_zero(RValue *v) { memset(v, 0, sizeof *v); }
static void l_free(RValue *v) { ((L_Free)RVA(0x14028c220))(v); }
static RValue *l_false(RValue *ret) { ret->v.real = 0; ret->flags = 0; ret->kind = 0; return ret; }

/* A plain number (real, int32, int64, bool) -> double. */
static int l_num(const RValue *v, double *x)
{
    unsigned k = v->kind & 0xffffff;
    if (k == 0 || k == 13) { *x = v->v.real; return 1; }
    if (k == 7) { *x = (double)(int)v->v.i64; return 1; }
    if (k == 10) { *x = (double)v->v.i64; return 1; }
    return 0;
}

/* inst.var as a number (0 when it isn't one). */
static int l_var_num(RValue *inst, unsigned long long var_slot, double *x)
{
    RValue t;
    int ok;
    l_zero(&t);
    ((VarGet)RVA(0x1478bbd70))(inst, L_VAR(var_slot), L_NOIDX, &t, 0, 0);
    ok = l_num(&t, x);
    l_free(&t);
    return ok;
}

static int l_truthy(RValue *v) { return ((ToBool)RVA(0x147871cf0))(v) != 0; }

/* ======================================================================================================================
 * SU-0212 (Diabolism / Straight Up / Unstoppable Force) and SU-0289 (Master of Spellmanes): "cannot be Sealed".
 * The game lets the seal land and the spell-gem manager's Step (obj_spellgem_manager Step_0) clears it on its next
 * pass, so everything that reads gem.sealed in between sees a sealed gem. These hooks make the reads answer "not
 * sealed" for the gems the Step would clear, using the Step's own tests:
 *   Astral Dimension (spell 288; only with SU-0137 on), Unstoppable Force (is_ultimate && perk 313),
 *   Straight Up (inv_SpellIsBooze(spellid) && perk 608), Diabolism (spellid 431-435 && perk 292),
 *   Master of Spellmanes ((enemy side has trait 1815 && bc_AllRace("Spellmane", 0)) ||
 *                         (your side has it && bc_AllRace("Spellmane", 1))).
 * The read hooks have no self/other for GML calls, so the script-based parts (perk levels, the Spellmanes test, the
 * Booze test per spell id) are refreshed by the Step itself (its trait-1815 AnyEnemyHasPassive call, once per tick)
 * and only read here. A refresh older than 100 ms counts as absent (only the Astral Dimension rule then applies). */
static struct { ULONGLONG tick; int p313, p608, p292, spellmanes; } l_seal;
static unsigned char l_booze[1024];                                 /* by spell id: 0 unknown, 1 no, 2 yes */

static int l_seal_fresh(void) { return l_seal.tick && GetTickCount64() - l_seal.tick <= 100; }

static int l_gem_unsealable(RValue *gem)
{
    double sid;
    int s;
    if (!gem || !l_var_num(gem, L_V_SPELLID, &sid)) return 0;      /* not a spell gem */
    s = (int)sid;
    if (L_SLOT_ON(L_SLOT_0137) && s == 288) return 1;               /* Astral Dimension */
    if (!l_seal_fresh()) return 0;
    if (L_SLOT_ON(L_SLOT_0212_FLAG)) {
        if (l_seal.p313) {
            RValue u;
            int ult;
            l_zero(&u);
            ((VarGet)RVA(0x1478bbd70))(gem, L_VAR(L_V_IS_ULTIMATE), L_NOIDX, &u, 0, 0);
            ult = l_truthy(&u);
            l_free(&u);
            if (ult) return 1;                                      /* Unstoppable Force */
        }
        if (l_seal.p608 && s >= 0 && s < 1024 && l_booze[s] == 2) return 1;    /* Straight Up */
        if (l_seal.p292 && s >= 431 && s <= 435) return 1;          /* Diabolism */
    }
    if (L_SLOT_ON(L_SLOT_0289_READ) && l_seal.spellmanes) return 1; /* Master of Spellmanes */
    return 0;
}

/* Stands in for the gem.sealed reads (varget) in bc_CreatureCast, bc_CreatureStartOfTurn, bc_EventDamage,
 * bc_GetSpellGems, bc_OnAttack, bc_OnDeath and crit_attack / defense / intelligence / speed. (bc_CritCanCastSpell's
 * read is SU-0137's hook, which calls l_gem_unsealable too.) */
static void *hook_l_su0289_sealed(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    void *r = ((VarGet)RVA(0x1478bbd70))(inst, var_id, index, out, a5, a6);
    if (var_id == L_VAR(L_V_SEALED) && out && l_truthy(out) && l_gem_unsealable(inst))
        ((L_SetInt)RVA(0x14028c530))(out, 0);                       /* as SU-0137 does */
    return r;
}

/* scr_PerkLevel(id) > 0 (second argument undefined, as the Step passes it). */
static int l_perk(void *self, void *other, double id)
{
    RValue a0, a1, res, *a[2], *r;
    int on;
    l_zero(&a0); l_zero(&a1); l_zero(&res);
    a0.v.real = id; a1.kind = 5;
    a[0] = &a0; a[1] = &a1;
    r = ((GmlScript)RVA(0x1464eb110))(self, other, &res, 2, a);
    on = ((L_GtInt)RVA(0x14028ca10))(r ? r : &res, 0) != 0;
    l_free(&res);
    return on;
}

/* bc_AllRace("Spellmane", side) with the Step's own argument values. */
static int l_all_spellmane(void *self, void *other, unsigned long long side_const)
{
    RValue a0, a1, res, *a[2], *r;
    int on;
    l_zero(&a0); l_zero(&a1); l_zero(&res);
    ((L_Assign)RVA(0x14028c410))(&a0, (RValue *)RVA(0x149e25bb0));  /* "Spellmane" */
    ((L_Assign)RVA(0x14028c410))(&a1, (RValue *)RVA(side_const));
    a[0] = &a0; a[1] = &a1;
    r = ((GmlScript)RVA(0x140601da0))(self, other, &res, 2, a);
    on = l_truthy(r ? r : &res);
    l_free(&res); l_free(&a0); l_free(&a1);
    return on;
}

/* Stands in for the Step's scr_AnyEnemyHasPassive(1815) (Master of Spellmanes block, runs for every gem each pass):
 * returns the same answer and refreshes the cached rule state. self = the gem, other = the manager. */
static RValue *hook_l_su0289_step(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(0x141f0b2d0))(self, other, ret, argc, args);
    ULONGLONG now = GetTickCount64();
    RValue g;
    double sid;
    int enemy_has;
    if (!self) return r;
    enemy_has = l_truthy(r ? r : ret);
    if (now != l_seal.tick) {
        int sm = 0;
        if (enemy_has && l_all_spellmane(self, other, 0x149d529c0ULL)) sm = 1;          /* enemy side (0) */
        else if (call_gate((GmlScript)RVA(0x141f0a8a0), self, other, 1815.0)
                 && l_all_spellmane(self, other, 0x14992a870ULL)) sm = 1;               /* your side (1) */
        l_seal.spellmanes = sm;
        l_seal.p313 = l_perk(self, other, 313.0);
        l_seal.p608 = l_perk(self, other, 608.0);
        l_seal.p292 = l_perk(self, other, 292.0);
        l_seal.tick = now;
    }
    l_zero(&g); g.v.ptr = self; g.kind = 6;                          /* the gem as a value, as the Step builds it */
    if (l_var_num(&g, L_V_SPELLID, &sid) && sid >= 0 && sid < 1024 && !l_booze[(int)sid]) {
        RValue a0, res, *a[1], *b;
        l_zero(&a0); l_zero(&res);
        a0.v.real = (double)(int)sid;
        a[0] = &a0;
        b = ((GmlScript)RVA(0x141dbb120))(self, other, &res, 1, a);  /* inv_SpellIsBooze */
        l_booze[(int)sid] = l_truthy(b ? b : &res) ? 2 : 1;
        l_free(&res);
    }
    return r;
}

/* SU-0212 has no site of its own: this slot only says the patch is on. */
static void hook_l_su0212_flag(void) {}

/* ======================================================================================================================
 * SU-0271 Gemcutter: "YOUR creatures' Ultimate Spell Gems cannot be Sealed." The Step unseals every Ultimate gem when
 * either side has Gemcutter (scr_AnyAllyHasPassive(1988) || scr_AnyEnemyHasPassive(1988)). Each test now counts only
 * for gems of its own side: the ally test for your gems, the enemy test for enemy gems. self = the gem being
 * processed. Side = bc_SpellGemGetOwner(gem).slot (> 0 yours, 0 enemy); unknown owner -> the game's answer. */
static int l_gem_side(void *self, void *other)                       /* 1 yours, 0 enemy, -1 unknown */
{
    RValue g, res, *a[1], *owner;
    double x;
    int side = -1;
    l_zero(&g); l_zero(&res);
    g.v.ptr = self; g.kind = 6;
    a[0] = &g;
    owner = ((GmlScript)RVA(0x141644100))(self, other, &res, 1, a);  /* bc_SpellGemGetOwner */
    if (!owner) owner = &res;
    if ((owner->kind & 0xffffff) != 5 && !(l_num(owner, &x) && x < 0) && l_var_num(owner, L_V_SLOT, &x))
        side = x > 0 ? 1 : 0;
    l_free(&res);
    return side;
}

static RValue *l_gemcutter(void *self, void *other, RValue *ret, int argc, RValue **args,
                           unsigned long long fn, int wrong_side)
{
    RValue *r = ((GmlScript)RVA(fn))(self, other, ret, argc, args);
    RValue g;
    double sealed;
    if (!self || !l_truthy(r ? r : ret)) return r;
    l_zero(&g); g.v.ptr = self; g.kind = 6;
    if (!l_var_num(&g, L_V_SEALED, &sealed) || sealed == 0) return r;    /* nothing to unseal: answer unchanged */
    if (l_gem_side(self, other) == wrong_side) return l_false(ret);
    return r;
}
static RValue *hook_l_su0271_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return l_gemcutter(self, other, ret, argc, args, 0x141f0a8a0ULL, 0); }   /* your Gemcutter: not for enemy gems */
static RValue *hook_l_su0271_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return l_gemcutter(self, other, ret, argc, args, 0x141f0b2d0ULL, 1); }   /* enemy Gemcutter: not for your gems */

/* ======================================================================================================================
 * SU-0228 Dark Ritual / SU-0229 Death Siphon: Velox and Lagopus cast "stat-manipulating" gems, chosen by the spell's
 * BOOST / DEBOOST tag. These two give the caster stats but are tagged UTILITY. Stands in for the first tag test's
 * `string_pos("DEBOOST", tag) > 0` (bc_StartupCasting L153 Velox, L293 Lagopus): also true for spell 35 (Dark
 * Ritual) and, with SU-0229 on, 37 (Death Siphon). The gem's spellid value: [rbp+0x460] / [rbp+0x410], rbp = rsp+0x100. */
static char l_stat_spell(RValue *v, int n, RValue *spell)
{
    double s;
    if (((L_GtInt)RVA(0x14028ca10))(v, n)) return 1;
    if (n == 0 && l_num(spell, &s) && (s == 35 || (s == 37 && L_SLOT_ON(L_SLOT_0229_FLAG)))) return 1;
    return 0;
}
static char hook_l_su0228_velox(RValue *v, int n) { return l_stat_spell(v, n, (RValue *)(L_CALLER_RSP + 0x560)); }
static char hook_l_su0228_lagopus(RValue *v, int n) { return l_stat_spell(v, n, (RValue *)(L_CALLER_RSP + 0x510)); }
static void hook_l_su0229_flag(void) {}

/* ======================================================================================================================
 * SU-0272 Giftwrapped Army: "a random buff for each Mimic". bc_StartupBuffsDebuffs L1005 calls bc_GetRandomBuff(-1),
 * so repeats are possible; given the creature, bc_GetRandomBuff re-picks buffs it already has (up to 50 tries).
 * Pass the Mimic receiving the buff: global.crits[i], i = the loop index the L1006 add uses ([rsp+0x48]). */
static RValue *hook_l_su0272_randbuff(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x141168b80);                   /* bc_GetRandomBuff */
    RValue g, crit, *a[1], *r;
    double x;
    int i;
    if (argc != 1 || !args || !args[0] || !l_num(args[0], &x) || x != -1) return orig(self, other, ret, argc, args);
    i = ((L_ToInt)RVA(0x14028c580))((RValue *)(L_CALLER_RSP + 0x48));
    if (i < 1 || i > 6) return orig(self, other, ret, argc, args);
    l_zero(&g); l_zero(&crit);
    ((L_GlobalInst)RVA(0x140297c20))(&g, L_GLOBAL_OBJ);
    ((VarGet)RVA(0x1478bbd70))(&g, L_VAR(L_V_CRITS), i, &crit, 0, 0);
    l_free(&g);
    if ((crit.kind & 0xffffff) == 5 || (l_num(&crit, &x) && x < 0)) {
        l_free(&crit);
        return orig(self, other, ret, argc, args);
    }
    a[0] = &crit;
    r = orig(self, other, ret, 1, a);
    l_free(&crit);
    return r;
}

/* ======================================================================================================================
 * SU-0222 Spin the Wheel: "Whenever it is an enemy's turn, any random effects that fail ... are re-rolled". scr_Roll
 * L36 only tested "an enemy's turn and one of YOUR creatures has it"; the slot == 0 jump is removed (byte edit) and
 * this stands in for its scr_AnyAllyHasPassive(1765): on an enemy's turn (slot 0) your side's trait counts, on your
 * creature's turn (slot > 0) the enemy side's. */
static RValue *hook_l_su0222_luck(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *turn = ((L_GlobalRef)RVA(0x140297c10))(L_GLOBAL_OBJ, L_VAR(L_V_TURN));
    double slot;
    if (!turn || !l_var_num(turn, L_V_SLOT, &slot)) return l_false(ret);   /* no turn: the block used to be skipped */
    if (slot == 0) return ((GmlScript)RVA(0x141f0a8a0))(self, other, ret, argc, args);   /* scr_AnyAllyHasPassive */
    if (slot > 0) return ((GmlScript)RVA(0x141f0b2d0))(self, other, ret, argc, args);    /* scr_AnyEnemyHasPassive */
    return l_false(ret);
}

/* ======================================================================================================================
 * SU-0235 Shellbust: "takes damage equal to 150% of the amount REDUCED". bc_CreatureCast L9409-L9420 builds one
 * bc_EventLoseDefense per target k, L9422-L9432 then deals big_mult(amount[k], 1.5) as damage, with amount = the
 * planned loss. The builder drops the loss (returns -1) when it is prevented or turned into a gain, redirects it by
 * changing the event's creature (Reflection), and resizes its amount. Record per target the event's final amount
 * (0 when dropped or redirected) and use it in the multiply. k = [rsp+0x2fd80] at both sites; keyed by the frame. */
#define L_SB_MAX 8
static struct { char *frame; int valid[L_SB_MAX]; double amount[L_SB_MAX]; } l_sb;

static RValue *hook_l_su0235_lose(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *c = L_CALLER_RSP;
    RValue *r = ((GmlScript)RVA(0x14104ff60))(self, other, ret, argc, args);   /* bc_EventLoseDefense */
    RValue *ev = r ? r : ret;
    int k = ((L_ToInt)RVA(0x14028c580))((RValue *)(c + 0x2fd80));
    unsigned kind = ev->kind & 0xffffff;
    double x;
    if (l_sb.frame != c) { memset(&l_sb, 0, sizeof l_sb); l_sb.frame = c; }
    if (k < 0 || k >= L_SB_MAX || argc < 2 || !args || !args[1]) return r;
    l_sb.valid[k] = 0;
    if (l_num(ev, &x) && x < 0) {                                   /* -1: prevented or converted */
        l_sb.amount[k] = 0; l_sb.valid[k] = 1;
    } else if (kind != 5) {                                         /* the event instance */
        RValue who;
        l_zero(&who);
        ((VarGet)RVA(0x1478bbd70))(ev, L_VAR(L_V_CREATURE), L_NOIDX, &who, 0, 0);
        if (!((L_Eq)RVA(0x14028c8d0))(&who, args[1])) { l_sb.amount[k] = 0; l_sb.valid[k] = 1; }   /* reflected */
        else if (l_var_num(ev, L_V_AMOUNT, &x)) { l_sb.amount[k] = x > 0 ? x : 0; l_sb.valid[k] = 1; }
        l_free(&who);
    }
    return r;
}

static RValue *hook_l_su0235_mult(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *c = L_CALLER_RSP;
    GmlScript big_mult = (GmlScript)RVA(0x1417a2e70);
    int k = ((L_ToInt)RVA(0x14028c580))((RValue *)(c + 0x2fd80));
    RValue amt, *a[2];
    if (l_sb.frame != c || k < 0 || k >= L_SB_MAX || !l_sb.valid[k] || argc != 2 || !args || !args[1])
        return big_mult(self, other, ret, argc, args);
    l_sb.valid[k] = 0;
    l_zero(&amt); amt.v.real = l_sb.amount[k];
    a[0] = &amt; a[1] = args[1];
    return big_mult(self, other, ret, 2, a);
}
