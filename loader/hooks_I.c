/* Hook batch I (errata round 2, damage pipeline; see research/build_hooks_I.py). Included by hooks.c after the earlier
 * batches; reuses RValue / GmlScript / VarGet / RVA / CmpInt / CmpEqInt / ToBool (hooks.c), e_var / e_truthy /
 * e_call / e_set_bool (hooks_E.c) and f1_list_get (hooks_F1.c). Every hook keeps the exact signature of the callee it
 * stands in for and falls back to the original behaviour when anything is unexpected. Slots: 0x149ed88d0-0x149ed8917.
 * SU-0267 Emerald Attunement and SU-0290 Mesmer are byte edits only (no C). */

#define I_HAS_PASSIVE    0x14202c2c0   /* scr_CritHasPassive(creature, id[, alive_only]) */
#define I_ANY_ALLY       0x141f0a8a0   /* scr_AnyAllyHasPassive(id): first holder in crits[1..6], or false */
#define I_ANY_ENEMY      0x141f0b2d0   /* scr_AnyEnemyHasPassive(id): first holder in enemies[1..6], or false */
#define I_HAS_RELIC_PERK 0x14202d600   /* scr_CritHasRelicPerk(creature, relic, perk) */
#define I_BIG_MULT       0x1417a2e70   /* big_mult(a, b) script */
#define I_SUB            0x140290910   /* runtime: dst -= src */
#define I_EQ             0x14028c8d0   /* runtime: value == value */
#define I_NE             0x1402954d0   /* runtime: value != value */
#define I_VARSET         0x1478bc260
#define I_SLOT_VAR       0x1499e0aa8   /* creature.slot: 0 = enemy side, > 0 = your side */
#define I_SOURCE_VAR     0x1499e0c38   /* damage event fields */
#define I_CREATURE_VAR   0x1499e3228
#define I_AMOUNT_VAR     0x1499c91b8
#define I_STRENGTH_VAR   0x1499c8598   /* 1 strong, 0 weak, -1 neutral */
#define I_CRITS_VAR      0x1499e0668   /* global.crits   (your party, 1..6) */
#define I_ENEMIES_VAR    0x1499e06a8   /* global.enemies (1..6) */
#define I_ED_SELF        0x21ef8       /* bc_EventDamage: the event (self) value at [frame + this] */
#define I_ED_RET         0x30488       /* bc_EventDamage: its own return address at [frame + this] */
#define I_RELEASE_RET    0x140bb12f9   /* return address of the Defer Pain release call (bc_CreatureStartOfTurn L1927) */

typedef char (*IValCmp)(RValue *a, RValue *b);
typedef void *(*IVarSet)(RValue *inst, int var_id, int index, RValue *value);
typedef void *(*IOp2)(RValue *dst, RValue *src);

static void i_real(RValue *v, double d) { memset(v, 0, sizeof *v); v->v.real = d; }
static RValue *i_false(RValue *r) { e_set_bool(r, 0); return r; }

/* Plain values (no reference count): real, struct/instance, int32, int64, bool, ref. */
static int i_plain(const RValue *v)
{
    unsigned k = v->kind & 0xffffff;
    return k == 0 || k == 6 || k == 7 || k == 10 || k == 13 || k == 15;
}

/* 1 = your side (slot > 0), 0 = enemy side (slot == 0), -1 = no usable slot. */
static int i_side(RValue *inst)
{
    RValue s = e_var(inst, I_SLOT_VAR);
    unsigned k = s.kind & 0xffffff;
    if (k != 0 && k != 7 && k != 10 && k != 13) return -1;
    if (((CmpEqInt)RVA(0x14028c8f0))(&s, 0)) return 0;
    if (((CmpInt)RVA(0x14028ca10))(&s, 0)) return 1;
    return -1;
}

/* ---- SU-0297 Ravish / SU-0270 Father Shadow ------------------------------------------------------------------- */
/* Ravish: "After this creature takes damage, it deals damage to the enemy ..."; Father Shadow: "After this creature
 * damages an enemy with an attack or spell, ...". Neither gate in bc_EventDamage (L7050 / L6547) compares sides, so a
 * Confused ally, a Stand As One copy or the holder's own hit set them off. Each stands in for the gate's
 * scr_CritHasPassive call and answers false when the event's source and creature are on the same side (both gates
 * test source > -1 first). Unknown sides: the game's answer. */
static RValue *i_enemy_only(char *frame, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *ev = (RValue *)(frame + I_ED_SELF);
    RValue src = e_var(ev, I_SOURCE_VAR), cr = e_var(ev, I_CREATURE_VAR);
    int a = i_side(&src), b = i_side(&cr);
    if (a >= 0 && b >= 0 && a == b) return i_false(ret);
    return ((GmlScript)RVA(I_HAS_PASSIVE))(self, other, ret, argc, args);
}
static RValue *hook_i_su0297_ravish(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return i_enemy_only((char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args);
}
static RValue *hook_i_su0270_father(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return i_enemy_only((char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args);
}

/* ---- SU-0303 Savior ------------------------------------------------------------------------------------------- */
/* "This creature takes 50% of the damage in place of your other creatures from attacks and spells." bc_EventDamage
 * L7149 halves the hit when the damaged creature's side has a holder, and only at L7160 skips the forward when the
 * holder is the damaged creature itself, so hits on a Savior lost half their damage. Stands in for the four holder
 * lookups (L7149 gate, L7154 / L7158 holder): when the game's first holder is the damaged creature, the next holder
 * on that side is returned instead, or false (the bool the lookup returns for "none") when there is no other. */
static RValue *i_savior(unsigned long long orig, unsigned long long list_var, char *frame,
                        void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(orig))(self, other, ret, argc, args);
    RValue *v = r ? r : ret, cr, c, *ha[2];
    IValCmp eq = (IValCmp)RVA(I_EQ);
    int i;
    if (argc < 1 || !args || !args[0] || !e_truthy(r, ret) || !i_plain(v)) return r;
    cr = e_var((RValue *)(frame + I_ED_SELF), I_CREATURE_VAR);
    if (!eq(v, &cr)) return r;                             /* holder is another creature: as the game */
    for (i = 1; i <= 6; i++) {
        if (!f1_list_get(list_var, i, &c) || eq(&c, &cr)) continue;
        ha[0] = &c; ha[1] = args[0];
        if (e_call(I_HAS_PASSIVE, self, other, 2, ha)) {
            if (!i_plain(&c)) return r;
            *v = c;
            return v;
        }
    }
    v->v.i64 = 0; v->flags = 0; v->kind = 13;              /* none: false */
    return v;
}
static RValue *hook_i_su0303_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return i_savior(I_ANY_ENEMY, I_ENEMIES_VAR, (char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args);
}
static RValue *hook_i_su0303_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return i_savior(I_ANY_ALLY, I_CRITS_VAR, (char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args);
}

/* ---- SU-0225 Materium, Shifting Gem of Aurum rank 30 ---------------------------------------------------------- */
/* "The bearer takes damage as if it is strong against the enemy's class." The game handles it only in the neutral
 * branch of the class step (L3995-L3997: amount -= amount x 0.5, strength = 0); hits that were strong against the
 * bearer (strength 1, amount x2) skip that branch and stayed doubled. Stands in for the Details Matter lookup at L4005
 * (one of the two runs for every hit that reaches it): on a strong hit on a rank-30 bearer it first brings the hit to
 * half of a neutral hit (amount -= amount x 0.75, the cut SU-0057 uses for strong hits) and marks it weak, exactly as
 * the neutral branch does; then the lookup runs unchanged (with Details Matter on top, SU-0057 then cuts nothing). */
static void i_materium(char *frame, void *self, void *other)
{
    RValue *ev = (RValue *)(frame + I_ED_SELF);
    RValue st = e_var(ev, I_STRENGTH_VAR), cr, amt, f, bonus, *br, *a[3], relic, perk;
    unsigned k;
    if (!((CmpEqInt)RVA(0x14028c8f0))(&st, 1)) return;     /* not a strong hit */
    cr = e_var(ev, I_CREATURE_VAR);
    i_real(&relic, 15.0); i_real(&perk, 3.0);
    a[0] = &cr; a[1] = &relic; a[2] = &perk;
    if (!e_call(I_HAS_RELIC_PERK, self, other, 3, a)) return;
    amt = e_var(ev, I_AMOUNT_VAR);
    k = amt.kind & 0xffffff;
    if (k != 0 && k != 7 && k != 10) return;
    i_real(&f, 0.75); memset(&bonus, 0, sizeof bonus);
    a[0] = &amt; a[1] = &f;
    br = ((GmlScript)RVA(I_BIG_MULT))(self, other, &bonus, 2, a);
    ((IOp2)RVA(I_SUB))(&amt, br ? br : &bonus);
    ((IVarSet)RVA(I_VARSET))(ev, *(int *)RVA(I_AMOUNT_VAR), (int)0x80000000, &amt);
    i_real(&st, 0.0);
    ((IVarSet)RVA(I_VARSET))(ev, *(int *)RVA(I_STRENGTH_VAR), (int)0x80000000, &st);
}
static RValue *hook_i_su0225_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    i_materium((char *)_AddressOfReturnAddress() + 8, self, other);
    return ((GmlScript)RVA(I_ANY_ENEMY))(self, other, ret, argc, args);
}
static RValue *hook_i_su0225_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    i_materium((char *)_AddressOfReturnAddress() + 8, self, other);
    return ((GmlScript)RVA(I_ANY_ALLY))(self, other, ret, argc, args);
}

/* ---- SU-0260 Defer Pain --------------------------------------------------------------------------------------- */
/* "When this creature takes damage, 90% of the damage is delayed until the start of its next turn." The L6110 gate
 * also required creature != creatureturn, so nothing taken during its own turn was delayed. That test exists for the
 * release hit (bc_CreatureStartOfTurn L1927 calls bc_EventDamage directly, at the holder's own turn start), which must
 * not be delayed again. Stands in for the != compare: the game's answer for the release hit (identified by
 * bc_EventDamage's own return address, so nested hits inside it are not mistaken for it), true for every other hit. */
static char hook_i_su0260_turn_ne(RValue *a, RValue *b)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    if (*(void **)(frame + I_ED_RET) == (void *)RVA(I_RELEASE_RET))
        return ((IValCmp)RVA(I_NE))(a, b);
    return 1;
}

/* ---- SU-0178 I HATE YOU !@#$ING ALL --------------------------------------------------------------------------- */
/* Both halves (bc_CreatureEndOfTurn L1310: the end-of-turn Provoke; bc_EventDamage L2528: 90% less damage taken while
 * Provoking) were `slot > 0 && ... scr_AnyAllyHasPassive(610)`, so an enemy holder did nothing. The slot tests are
 * dropped (byte edits); these stand in for the AnyAlly lookup and ask the creature's own side instead. */
static RValue *i_own_side(RValue *c, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    int s = c ? i_side(c) : -1;
    if (s == 1) return ((GmlScript)RVA(I_ANY_ALLY))(self, other, ret, argc, args);
    if (s == 0) return ((GmlScript)RVA(I_ANY_ENEMY))(self, other, ret, argc, args);
    return i_false(ret);                                   /* no usable side: the gate stays shut, as for slot <= 0 */
}
/* bc_EventDamage: the damaged creature (event.creature) */
static RValue *hook_i_su0178_damage(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue cr = e_var((RValue *)(frame + I_ED_SELF), I_CREATURE_VAR);
    return i_own_side(&cr, self, other, ret, argc, args);
}
/* bc_CreatureEndOfTurn: the creature ending its turn (global creatureturn, whose value pointer the function keeps at
 * [frame + 0x48]; the L1312 Provoke uses the same) */
static RValue *hook_i_su0178_endturn(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    return i_own_side(*(RValue **)(frame + 0x48), self, other, ret, argc, args);
}
