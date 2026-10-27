/* Hook batch R: relic ranks, perks, guild (see research/hook_batches.json, research/build_hooks_R.py).
 * Included by hooks.c, after the shared typedefs (RValue, GmlScript, VarGet, RVA, call_gate, CmpInt, CmpEqInt, ToBool).
 * Every hook stands in for exactly one game call and keeps that callee's signature. */

typedef void *(*AddInt)(RValue *dst, int n);              /* the runtime's "dst += int" helper */

/* Slots the batch-R trampolines use to hand over the caller's rbp (rbp-framed callers). */
#define R_RBP_SLOT(n) ((char **)RVA(0x149ed8300 + 8 * (n)))

static RValue r_real(double d) { RValue v; memset(&v, 0, sizeof v); v.v.real = d; return v; }

/* scr_RelicHasRelicPerk(relic_object, relic, perk) -> bool */
static int r_relic_rank(void *self, void *other, RValue *relic_obj, int relic, int perk)
{
    GmlScript f = (GmlScript)RVA(0x14664f720);
    ToBool to_bool = (ToBool)RVA(0x147871cf0);
    RValue a = r_real(relic), b = r_real(perk), res, *r;
    RValue *args[3];
    args[0] = relic_obj; args[1] = &a; args[2] = &b;
    memset(&res, 0, sizeof res);
    r = f(self, other, &res, 3, args);
    return to_bool(r ? r : &res) != 0;
}

static RValue *r_false(RValue *ret) { ret->v.real = 0; ret->flags = 0; ret->kind = 0; return ret; }

/* --- SU-0007 Brambleskin rank 100 / SU-0008 Fable rank 80 (on-death half) ---------------------------------------
 * Both rank tests run on a creature that has just died, but call scr_CritHasRelicPerk with 3 arguments, and that helper
 * returns false for hp <= 0 unless a 4th "allow dead" argument is true. The other on-death relic tests pass the game's
 * static true (0x1498e0f60); these two get the same. */
static RValue *hook_su0007_relicperk_allow_dead(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x14202d600);                   /* scr_CritHasRelicPerk */
    if (argc == 3) {
        RValue *a4[4];
        a4[0] = args[0]; a4[1] = args[1]; a4[2] = args[2]; a4[3] = (RValue *)RVA(0x1498e0f60);
        return orig(self, other, ret, 4, a4);
    }
    return orig(self, other, ret, argc, args);
}
static RValue *hook_su0008_relicperk_allow_dead(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return hook_su0007_relicperk_allow_dead(self, other, ret, argc, args);
}

/* --- SU-0006 Lamora rank 90 -------------------------------------------------------------------------------------
 * "Casts spells as if it has 30% more Intelligence for each enemy with Blighted" (rank 90). The three calculators
 * count Blighted enemies for any Lamora relic caster (isrelic == 5) with no rank test. These hooks stand in for the
 * scr_CritHasCondition(enemy, 16) call of that count: if the caster (the Lamora relic object) is not rank 90, no
 * enemy counts, so the bonus is 0. Caster value: bc_SpellDamage [rsp+0xb728]; bc_SpellHealing [rbp-0x50];
 * bc_SpellStat [rbp-0x40] (rbp handed over by the trampoline). */
static RValue *r_lamora90(void *self, void *other, RValue *ret, int argc, RValue **args, RValue *caster)
{
    GmlScript orig = (GmlScript)RVA(0x14202b010);                   /* scr_CritHasCondition */
    if (caster && !r_relic_rank(self, other, caster, 5, 9))
        return r_false(ret);
    return orig(self, other, ret, argc, args);
}
static RValue *hook_su0006_damage(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    return r_lamora90(self, other, ret, argc, args, (RValue *)(caller_rsp + 0xb728));
}
static RValue *hook_su0006_healing(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return r_lamora90(self, other, ret, argc, args, (RValue *)(*R_RBP_SLOT(0) - 0x50));
}
static RValue *hook_su0006_stat(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return r_lamora90(self, other, ret, argc, args, (RValue *)(*R_RBP_SLOT(1) - 0x40));
}

/* --- SU-0085 Covenant (perk 289) --------------------------------------------------------------------------------
 * "If your creatures have cast each Rune spell at least once in the current battle, they activate your creatures'
 * on-attack effects 1 additional time." bc_CreatureCast's Rune case adds the extra pass (n += 1, L9798) once all five
 * Runes were cast, for any caster, and never tests the perk. This hook stands in for that n += 1: only for a caster on
 * your side, and only while you have Covenant. Frame of bc_CreatureCast: self [rsp+0x42990], other [rsp+0x42998],
 * caster value [rsp+0x2fc60]. */
static void *hook_su0085_covenant_add(RValue *dst, int n)
{
    AddInt orig = (AddInt)RVA(0x1402f4230);
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    void *self = *(void **)(caller_rsp + 0x42990), *other = *(void **)(caller_rsp + 0x42998);
    RValue *caster = (RValue *)(caller_rsp + 0x2fc60);
    RValue slot;
    memset(&slot, 0, sizeof slot);
    varget(caster, *(int *)RVA(0x1499e0aa8), (int)0x80000000, &slot, 0, 0);   /* caster.slot */
    if (!((CmpInt)RVA(0x14028ca10))(&slot, 0))                                /* enemy caster: no perks */
        return dst;
    if (!call_gate((GmlScript)RVA(0x1464eb110), self, other, 289.0))          /* scr_PerkLevel(289) */
        return dst;
    return orig(dst, n);
}

/* --- SU-0127 Bolster (Hell Knight, perk 58) ---------------------------------------------------------------------
 * "Your creatures take 1% less damage from attacks and spells for every 1% of Health they're missing." The block has
 * no damage-type test, so it also cut indirect damage. This hook stands in for its scr_PerkLevel(58) gate: for a hit
 * that is not an attack (dtype 0) or a spell (dtype 1) it reports level 0. bc_EventDamage's self value (the damage
 * event) is at [caller rsp + 0x21ef8]; dtype is variable slot 0x149934038. */
static RValue *hook_su0127_bolster_gate(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x1464eb110);                   /* scr_PerkLevel */
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    CmpEqInt eq_int = (CmpEqInt)RVA(0x14028c8f0);
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    RValue dtype;
    memset(&dtype, 0, sizeof dtype);
    varget((RValue *)(caller_rsp + 0x21ef8), *(int *)RVA(0x149934038), (int)0x80000000, &dtype, 0, 0);
    if (!eq_int(&dtype, 0) && !eq_int(&dtype, 1))
        return r_false(ret);
    return orig(self, other, ret, argc, args);
}

/* scr_CritHasCondition(crit, cond) -> bool */
static int r_has_cond(void *self, void *other, RValue *crit, int cond)
{
    GmlScript f = (GmlScript)RVA(0x14202b010);
    ToBool to_bool = (ToBool)RVA(0x147871cf0);
    RValue c = r_real(cond), res, *r;
    RValue *args[2];
    args[0] = crit; args[1] = &c;
    memset(&res, 0, sizeof res);
    r = f(self, other, &res, 2, args);
    return to_bool(r ? r : &res) != 0;
}

/* --- SU-0009 Starwrath rank 100 ---------------------------------------------------------------------------------
 * "Enemies have a 10% chance to Attack and Cast spells as if they have Confused even if they don't have this debuff."
 * The code sets the redirect chance to 10 for every enemy action once rank 100 is owned, so a really Confused enemy
 * drops from 50% to 10%. These hooks stand in for that `chance = 10` (int set): an actor that has Confused (19)
 * keeps its normal chance. bc_CreatureAttack frame: actor [rsp+0x68], self [rsp+0x88a0], other [rsp+0x88a8];
 * bc_CreatureCast: caster [rsp+0x2fc60], self [rsp+0x42990], other [rsp+0x42998]. */
static void *r_starwrath(RValue *dst, int n, char *caller_rsp, int actor_off, int self_off)
{
    AddInt set_int = (AddInt)RVA(0x14028c530);                      /* "dst = int" (same shape as the add helper) */
    void *self = *(void **)(caller_rsp + self_off), *other = *(void **)(caller_rsp + self_off + 8);
    if (r_has_cond(self, other, (RValue *)(caller_rsp + actor_off), 19))
        return dst;                                                 /* Confused: keep the normal chance */
    return set_int(dst, n);
}
static void *hook_su0009_attack(RValue *dst, int n)
{
    return r_starwrath(dst, n, (char *)_AddressOfReturnAddress() + 8, 0x68, 0x88a0);
}
static void *hook_su0009_cast(RValue *dst, int n)
{
    return r_starwrath(dst, n, (char *)_AddressOfReturnAddress() + 8, 0x2fc60, 0x42990);
}

/* --- SU-0042 Reliquary heal upgrade (+ Abandoned Altar) ---------------------------------------------------------
 * bc_EventHeal L249 computes the Reliquary heal bonus for a heal from a Relic creature into a scratch local
 * ([rbp+0x210] = amount x 0.01 x global.reliquary_heal) and L251 doubles it with Abandoned Altar, but nothing adds the
 * scratch to the heal's bonus pool ([rbp+0x1d0], the pool every other heal bonus uses). Two hooks, both inside the
 * block: after the L249 assign, pool += scratch; before the L251 doubling (Altar only), pool += scratch again. Net:
 * +1x the bonus, +2x with Abandoned Altar ("100% more benefit from Reliquary Upgrades"). rbp handed over by the
 * trampolines (bc_EventHeal is rbp-framed). */
typedef void *(*RvBin)(RValue *a, RValue *b);              /* runtime RValue helpers: assign / += / *= */
static void r_heal_pool_add(char *rbp)
{
    ((RvBin)RVA(0x14028c630))((RValue *)(rbp + 0x1d0), (RValue *)(rbp + 0x210));
}
static void *hook_su0042_assign(RValue *dst, RValue *src)
{
    void *r = ((RvBin)RVA(0x14028c410))(dst, src);
    r_heal_pool_add(*R_RBP_SLOT(2));
    return r;
}
static void *hook_su0042_double(RValue *dst, RValue *factor)
{
    r_heal_pool_add(*R_RBP_SLOT(3));
    return ((RvBin)RVA(0x140290b30))(dst, factor);
}
