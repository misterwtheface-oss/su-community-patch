/* Hook batch B2 (round 2; see research/hook_batches.json): relic side tests, Fable 50, Impending Victory, Master of
 * Stags (Prism), Touch of Red. Included by hooks.c after the round-1 files; reuses RValue / GmlScript / VarGet / RVA /
 * ToBool / CmpInt and hooks_E.c's e_var / e_is_enemy / e_truthy / e_call / e_side_has / e_set_bool.
 * Every hook keeps the exact signature of the callee it stands in for and falls back to the original behaviour when
 * anything is unexpected. Built by research/build_hooks_B2.py (research/hooks_B2.json). */

#define B2_HAS_RELIC_PERK 0x14202d600   /* scr_CritHasRelicPerk(creature, relic, rank[, allow_dead]) */
#define B2_PERK_LEVEL     0x1464eb110   /* scr_PerkLevel(perk[, side]) */
#define B2_ALL_RACE       0x140601da0   /* bc_AllRace(race string, side: 0 enemy / 1 yours) */
#define B2_NTH_STAT       0x14612aad0   /* scr_GetCritNthHighestStatAmt(creature, n, false) */
#define B2_IS_EQUIPMENT   0x141dbbc80   /* inv_SpellIsEquipment(spell id) */
#define B2_CRIT_INT       0x1417cf710   /* crit_intelligence(creature) */
#define B2_SUB_INT        0x1402c47f0   /* runtime: out = in - n (int n); returns out */
#define B2_ASSIGN         0x14028c410   /* runtime: dst = src */
#define B2_GT_INT         0x14028ca10   /* runtime: value > int */
#define B2_UNDEFINED      0x1498e0f50   /* static undefined value (the "side omitted" argument) */
#define B2_STAG_STR       0x149d5cc60   /* the game's global "Stag" string value */
#define B2_SPELL_ID_VAR   0x1499e0b28   /* variable id slot: a spell gem's spell id */

typedef RValue *(*B2SubInt)(RValue *out, RValue *in, int n);
typedef void (*B2Assign)(RValue *dst, RValue *src);

static void b2_real(RValue *v, double x) { memset(v, 0, sizeof *v); v->v.real = x; }

/* Numeric value of an RValue: real 0, int32 7, int64 10, bool 13. ok = 0 for anything else. */
static double b2_num(const RValue *v, int *ok)
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

/* 1 when both values are creatures on the same side (slot 0 = enemy side, > 0 = yours) */
static int b2_same_side(RValue *a, RValue *b) { return e_is_enemy(a) == e_is_enemy(b); }

/* scr_CritHasRelicPerk(creature, relic, rank) with three arguments, as the game's own gates call it. */
static int b2_has_relic_perk(void *self, void *other, RValue *creature, double relic, double rank)
{
    RValue r, k, *a[3];
    b2_real(&r, relic); b2_real(&k, rank);
    a[0] = creature; a[1] = &r; a[2] = &k;
    return e_call(B2_HAS_RELIC_PERK, self, other, 3, a);
}

/* ---- SU-0087 Amalgam ranks 50 / 60 / 100: only an enemy's Inverted counts. Stands in for the rank gates
 * scr_CritHasRelicPerk(bearer, 30, rank) in bc_EventDamage (R60 extra heal, R50 potency kept, R100 re-apply) and
 * bc_EventHeal (R50, R100). The Inverted creature is the event's source; when it is on the bearer's own side the gate
 * is false, so your own Inverted creatures no longer heal enemies twice, keep their Inverted, or get it back. */
static RValue *b2_amalgam(RValue *event_self, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue src = e_var(event_self, E_SOURCE_VAR);
    int ok; double s = b2_num(&src, &ok);
    if (argc >= 1 && !(ok && s < 0) && b2_same_side(&src, args[0])) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(B2_HAS_RELIC_PERK))(self, other, ret, argc, args);
}

/* bc_EventDamage: self value at [caller rsp + 0x21ef8] */
static RValue *hook_su0087_damage(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    return b2_amalgam((RValue *)(frame + 0x21ef8), self, other, ret, argc, args);
}

/* bc_EventHeal: self value at [caller rsp + 0x50] */
static RValue *hook_su0087_heal(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    return b2_amalgam((RValue *)(frame + 0x50), self, other, ret, argc, args);
}

/* ---- SU-0088 "After the bearer attacks, this relic attacks that target / the enemy": no follow-up when attacker and
 * target are on the same side (a Confused bearer hitting an ally). Stands in for the six rank gates in bc_OnAttack
 * whose block makes the relic attack; bc_OnAttack's attacker / target arguments are at [caller rsp + 0x168f0 / 0x16900]. */
static RValue *hook_su0088_relic_attack(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    if (b2_same_side((RValue *)(frame + 0x168f0), (RValue *)(frame + 0x16900))) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(B2_HAS_RELIC_PERK))(self, other, ret, argc, args);
}

/* ---- SU-0030 Fable rank 50 "on-debuff effects activate 1 additional time". The debuff case of bc_ExecuteEvents
 * repeats bc_OnBuffDebuff while i <= scr_PerkLevel(367) (Unbound Hatred) and never counts Fable, unlike the buff case
 * (scr_CritHasRelicPerk(event.creature, 29, 5) adds one pass). Stands in for that scr_PerkLevel call: the level reads
 * one higher when the debuffed creature bears Fable rank 50, so the passes add up as in the buff case. The loop
 * re-evaluates the bound every pass, and so does this hook. Event value at [caller rsp + 0x98e8]. */
static RValue *hook_su0030_perk_level(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue *r = ((GmlScript)RVA(B2_PERK_LEVEL))(self, other, ret, argc, args);
    RValue c = e_var((RValue *)(frame + 0x98e8), E_CREATURE_VAR);
    int ok; double lv = b2_num(r ? r : ret, &ok);
    if (ok && b2_has_relic_perk(self, other, &c, 29.0, 5.0)) { b2_real(ret, lv + 1.0); return ret; }
    return r;
}

/* ---- SU-0131 Impending Victory "50% of the potency of your creatures' Arsenal spells is based on their highest stat".
 * The game blends only in bc_SpellDamage (L47-51: scr_PerkLevel(596) > 0 && inv_SpellIsEquipment(spell.id) ->
 * stat = 0.5 x highest + 0.5 x stat). Stands in for crit_intelligence(caster) where bc_SpellHealing (L16) and
 * bc_SpellStat (L22) read the potency stat, and applies the same test and blend. rbp = args[0] + 0x50 / 0x40 (args[0]
 * is the caster's argument copy at [rbp-0x50] / [rbp-0x40]); the spell argument copy is at [rbp+0x60] in both. */
static RValue *b2_impending(size_t arg0_off, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(B2_CRIT_INT))(self, other, ret, argc, args);
    RValue perk, side, lvv, *lr, id, one, no, hv, *hr, *pa[2], *ia[1], *ha[3];
    char *rbp; int ok1, ok2; double h, x;
    if (argc != 1 || !args || !args[0]) return r;
    rbp = (char *)args[0] + arg0_off;
    b2_real(&perk, 596.0); side = *(RValue *)RVA(B2_UNDEFINED); memset(&lvv, 0, sizeof lvv);
    pa[0] = &perk; pa[1] = &side;
    lr = ((GmlScript)RVA(B2_PERK_LEVEL))(self, other, &lvv, 2, pa);
    if (!((CmpInt)RVA(B2_GT_INT))(lr ? lr : &lvv, 0)) return r;
    id = e_var((RValue *)(rbp + 0x60), B2_SPELL_ID_VAR); ia[0] = &id;
    if (!e_call(B2_IS_EQUIPMENT, self, other, 1, ia)) return r;
    b2_real(&one, 1.0); b2_real(&no, 0.0); no.kind = 13; memset(&hv, 0, sizeof hv);
    ha[0] = args[0]; ha[1] = &one; ha[2] = &no;
    hr = ((GmlScript)RVA(B2_NTH_STAT))(self, other, &hv, 3, ha);
    h = b2_num(hr ? hr : &hv, &ok1); x = b2_num(r ? r : ret, &ok2);
    if (!ok1 || !ok2) return r;
    b2_real(ret, 0.5 * h + 0.5 * x);
    return ret;
}

static RValue *hook_su0131_healing(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return b2_impending(0x50, self, other, ret, argc, args); }

static RValue *hook_su0131_stat(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return b2_impending(0x40, self, other, ret, argc, args); }

/* ---- SU-0170 Master of Stags x Prism (user ruling: "100% more effective" doubles the numbers, so Prism uses 200% of
 * the potency-modifier stats). Each Prism block in bc_SpellDamage / bc_SpellHealing / bc_SpellStat is
 * if ((slot == 0 && scr_AnyEnemyHasPassive(902)) || (slot > 0 && scr_AnyAllyHasPassive(902))) stat = modifier_stat;
 * The gate hooks note whether the passing side also qualifies for Master of Stags (holds 1501 and bc_AllRace("Stag",
 * side), the game's own Master test); the assign hook right after the gate doubles the assigned stat once. Some of
 * these assigns are shared code tails, so the flag is cleared at every gate and consumed by the first assign. */
static int b2_prism_double;

static int b2_stags(void *self, void *other, int enemy)
{
    RValue id, side, *a[2];
    b2_real(&id, 1501.0);
    if (!e_side_has(enemy, self, other, &id)) return 0;
    b2_real(&side, enemy ? 0.0 : 1.0);
    a[0] = (RValue *)RVA(B2_STAG_STR); a[1] = &side;
    return e_call(B2_ALL_RACE, self, other, 2, a);
}

static RValue *b2_prism_gate(int enemy, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(enemy ? E_ANY_ENEMY : E_ANY_ALLY))(self, other, ret, argc, args);
    b2_prism_double = 0;
    if (e_truthy(r, ret) && b2_stags(self, other, enemy)) b2_prism_double = 1;
    return r;
}

static RValue *hook_su0170_prism_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return b2_prism_gate(1, self, other, ret, argc, args); }

static RValue *hook_su0170_prism_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return b2_prism_gate(0, self, other, ret, argc, args); }

static void hook_su0170_prism_assign(RValue *dst, RValue *src)
{
    int dbl = b2_prism_double, ok;
    double x;
    b2_prism_double = 0;
    ((B2Assign)RVA(B2_ASSIGN))(dst, src);
    if (!dbl) return;
    x = b2_num(dst, &ok);
    if (ok) b2_real(dst, 2.0 * x);
}

/* ---- SU-0176 Touch of Red "increased by 25% for each attack": the term is (hits - 1) x 0.25 (bc_CreatureAttack
 * L1253, the "- 1" is this call's int argument). Stands in for that subtract: with more than one attack in a row it
 * subtracts 0, so 3 attacks give +75% on each hit; a single attack keeps hits - 1 = 0 (the text needs "multiple"). */
static RValue *hook_su0176_hits(RValue *out, RValue *in, int n)
{
    B2SubInt sub = (B2SubInt)RVA(B2_SUB_INT);
    if (n == 1 && ((CmpInt)RVA(B2_GT_INT))(in, 1)) return sub(out, in, 0);
    return sub(out, in, n);
}
