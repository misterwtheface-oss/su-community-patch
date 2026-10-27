/* Hook batch E (see research/hook_batches.json): Elf "...And Other..." traits made global, side / stacking fixes,
 * minion conditions. Included by hooks.c; reuses RValue / GmlScript / VarGet / RVA / call_gate / CmpInt / CmpEqInt /
 * ToBool from there. Every hook keeps the exact signature of the callee it stands in for and falls back to the
 * original behaviour when anything is unexpected. Built by research/build_hooks_E.py (research/hooks_E.json). */

#define E_ANY_ALLY      0x141f0a8a0   /* scr_AnyAllyHasPassive(id)   : your side   */
#define E_ANY_ENEMY     0x141f0b2d0   /* scr_AnyEnemyHasPassive(id)  : enemy side  */
#define E_HAS_PASSIVE   0x14202c2c0   /* scr_CritHasPassive(creature, id[, alive_only]) */
#define E_HAS_CONDITION 0x14202b010   /* scr_CritHasCondition(creature, condition) */
#define E_IS_BUFF       0x141fa4c50   /* scr_ConditionIsBuff(condition) */
#define E_ROLL          0x146666e40   /* scr_Roll(chance) */
#define E_RANDOM_DEBUFF 0x141175450   /* bc_GetRandomDebuff(-1, target) */
#define E_VARGET        0x1478bbd70
#define E_TO_BOOL       0x147871cf0
#define E_EQ            0x14028c8d0   /* runtime "==" on two values */
#define E_SLOT_VAR      0x1499e0aa8   /* variable id slots */
#define E_SOURCE_VAR    0x1499e0c38
#define E_CREATURE_VAR  0x1499e3228

static void e_set_bool(RValue *r, int v) { r->v.real = v ? 1.0 : 0.0; r->flags = 0; r->kind = 0; }

static RValue e_var(RValue *inst, unsigned long long slot_va)
{
    RValue out; memset(&out, 0, sizeof out);
    ((VarGet)RVA(E_VARGET))(inst, *(int *)RVA(slot_va), (int)0x80000000, &out, 0, 0);
    return out;
}

/* 1 = enemy side (slot == 0), 0 = your side; -1 if the value has no usable slot */
static int e_is_enemy(RValue *inst)
{
    RValue s = e_var(inst, E_SLOT_VAR);
    return ((CmpEqInt)RVA(0x14028c8f0))(&s, 0) ? 1 : 0;
}

static int e_truthy(RValue *r, RValue *fallback) { return ((ToBool)RVA(E_TO_BOOL))(r ? r : fallback) != 0; }

/* call a GML script with explicit args; returns its truthiness */
static int e_call(unsigned long long fn_va, void *self, void *other, int argc, RValue **argv)
{
    RValue res, *r; memset(&res, 0, sizeof res);
    r = ((GmlScript)RVA(fn_va))(self, other, &res, argc, argv);
    return e_truthy(r, &res);
}

static int e_side_has(int enemy, void *self, void *other, RValue *id)
{
    RValue *a[1]; a[0] = id;
    return e_call(enemy ? E_ANY_ENEMY : E_ANY_ALLY, self, other, 1, a);
}

/* ---- SU-0093..0096, SU-0174, SU-0175 Elf "...And Other..." traits: global, as the text reads. Stands in for both
 * the AnyAlly and the AnyEnemy call of each trait's gate ((slot == 0 && AnyAlly) || (slot > 0 && AnyEnemy)): either
 * side holding the trait counts, so whichever branch the slot test picks, the gate is the same "anyone has it". */
static RValue *hook_e_either_side_passive(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(E_ANY_ALLY))(self, other, ret, argc, args);
    if (e_truthy(r, ret)) return r;
    return ((GmlScript)RVA(E_ANY_ENEMY))(self, other, ret, argc, args);
}

/* ---- SU-0124 Beelzebub / SU-0125 Leviathan: "when its master kills an enemy". Stands in for
 * scr_CritHasCondition(killer, 58 / 57) in bc_OnDeath (killer = arg0 at [rsp+0xe240], dying = arg1 at [rsp+0xe250]). */
static RValue *hook_e_minion_kill(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue *killer = (RValue *)(frame + 0xe240), *dying = (RValue *)(frame + 0xe250);
    if (e_is_enemy(killer) == e_is_enemy(dying)) { e_set_bool(ret, 0); return ret; }   /* same side: not an enemy */
    return ((GmlScript)RVA(E_HAS_CONDITION))(self, other, ret, argc, args);
}

/* ---- SU-0126 Spiderlings: "after this minion's master takes damage from an enemy". Stands in for
 * scr_CritHasCondition(creature, 45) at bc_EventDamage L6595; source from the event's self value [rsp+0x21ef8]. */
static RValue *hook_e_spiderling(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue src = e_var((RValue *)(frame + 0x21ef8), E_SOURCE_VAR);
    if (argc >= 1 && e_is_enemy(&src) == e_is_enemy(args[0])) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(E_HAS_CONDITION))(self, other, ret, argc, args);
}

/* ---- SU-0162 Haunting Memories: the trait needs its holder dead, but scr_CritHasPassive skips dead holders unless
 * its 3rd argument (alive_only, default 1) is 0. Stands in for scr_CritHasPassive(e, 878) in bc_CreatureEndOfTurn. */
static RValue *hook_e_haunting(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue alive_only, *a[3];
    if (argc != 2) return ((GmlScript)RVA(E_HAS_PASSIVE))(self, other, ret, argc, args);
    memset(&alive_only, 0, sizeof alive_only);               /* real 0.0 = allow dead */
    a[0] = args[0]; a[1] = args[1]; a[2] = &alive_only;
    return ((GmlScript)RVA(E_HAS_PASSIVE))(self, other, ret, 3, a);
}

/* ---- SU-0163 Horde: "This effect is not applied to creatures that have this trait". Stands in for the side gate
 * (AnyAlly / AnyEnemy(141)) in crit_speed; the creature whose Speed is computed is crit_speed's [rsp+0x68]. */
static int e_holds(void *self, void *other, RValue *who, double id)
{
    RValue idv, *a[2]; memset(&idv, 0, sizeof idv); idv.v.real = id;
    a[0] = who; a[1] = &idv;
    return e_call(E_HAS_PASSIVE, self, other, 2, a);
}
static RValue *hook_e_horde_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    if (e_holds(self, other, (RValue *)(frame + 0x68), 141.0)) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(E_ANY_ALLY))(self, other, ret, argc, args);
}
static RValue *hook_e_horde_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    if (e_holds(self, other, (RValue *)(frame + 0x68), 141.0)) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(E_ANY_ENEMY))(self, other, ret, argc, args);
}

/* ---- SU-0153 Periphery: "Your creatures always dodge / deal critical damage / take 50% more damage" — the code only
 * had the player-side case (who.slot > 0 && AnyAlly(603)). The slot test is removed and these stand in for AnyAlly:
 * the holder's own side is tested (AnyAlly for your creatures, AnyEnemy for an enemy). */
static RValue *e_periphery(RValue *who, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    int enemy = e_is_enemy(who);
    return ((GmlScript)RVA(enemy ? E_ANY_ENEMY : E_ANY_ALLY))(self, other, ret, argc, args);
}
static RValue *hook_e_periphery_dodge(void *self, void *other, RValue *ret, int argc, RValue **args)
{   /* bc_CreatureAttack L1535: who = the target, [rsp+0x98] */
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    return e_periphery((RValue *)(frame + 0x98), self, other, ret, argc, args);
}
static RValue *hook_e_periphery_taken(void *self, void *other, RValue *ret, int argc, RValue **args)
{   /* bc_EventDamage L5175: who = creature (the damaged one) */
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue c = e_var((RValue *)(frame + 0x21ef8), E_CREATURE_VAR);
    return e_periphery(&c, self, other, ret, argc, args);
}
static RValue *hook_e_periphery_crit(void *self, void *other, RValue *ret, int argc, RValue **args)
{   /* bc_EventDamage L5844: who = source (the attacker); the block already requires source > -1 */
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue s = e_var((RValue *)(frame + 0x21ef8), E_SOURCE_VAR);
    return e_periphery(&s, self, other, ret, argc, args);
}

/* ---- SU-0028 Master of Cataclysms (partial): "their traits [your all-Cataclysm party's]" — the sweep over the
 * timeline also rolled enemies' Wrath traits. Stands in for the 11 scr_CritHasPassive(creatureList[i], 2100..2110)
 * calls: only creatures on the master's side (the side of the turn creature, which the gate already tested) count.
 * Turn creature: bc_CreatureStartOfTurn's *(RValue **)[rsp+0xba58]. */
static RValue *hook_e_cataclysm(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue *turn = *(RValue **)(frame + 0xba58);
    if (argc >= 1 && turn && e_is_enemy(args[0]) != e_is_enemy(turn)) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(E_HAS_PASSIVE))(self, other, ret, argc, args);
}

/* ---- SU-0107 Disposability: "Your OTHER creatures' buffs persist through death" (user 2026-10-26: the holder's own
 * buffs and every minion do not). bc_HandleDeath L60-L67; dying creature at [rsp+0x70].
 * (a) side gate: a dying creature that holds Disposability itself is not protected; */
static RValue *hook_e_dispose_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    if (e_holds(self, other, (RValue *)(frame + 0x70), 512.0)) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(E_ANY_ALLY))(self, other, ret, argc, args);
}
static RValue *hook_e_dispose_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    if (e_holds(self, other, (RValue *)(frame + 0x70), 512.0)) { e_set_bool(ret, 0); return ret; }
    return ((GmlScript)RVA(E_ANY_ENEMY))(self, other, ret, argc, args);
}
/* (b) per condition: the block removes what "is a debuff"; it now removes everything that is not a buff (minions too).
 * Stands in for scr_ConditionIsDebuff(cond) at L64. */
static RValue *hook_e_dispose_not_buff(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    int buff = e_call(E_IS_BUFF, self, other, argc, args);
    e_set_bool(ret, !buff);
    return ret;
}

/* ---- SU-0146 Better, Faster, Stronger + Writhelings: "minions perform their effects twice" — the Writheling effect is
 * "afflicts a random enemy with a random debuff"; the BFS block repeated Pleasant Disease's random buff instead. The
 * block now picks from the enemies array and calls bc_EventDebuff (byte edits); this stands in for its
 * bc_GetRandomBuff(target) and returns bc_GetRandomDebuff(-1, target), the same call the Writheling loop makes. */
static RValue *hook_e_bfs_random_debuff(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue minus1, *a[2];
    if (argc < 1) return ret;
    memset(&minus1, 0, sizeof minus1); minus1.v.real = -1.0;
    a[0] = &minus1; a[1] = args[0];
    return ((GmlScript)RVA(E_RANDOM_DEBUFF))(self, other, ret, 2, a);
}

/* ---- SU-0156 Pumpkin Spice: "your creatures swap ..." — each side with a holder swaps once (the code stopped after
 * the first holder's side). Stands in for scr_CritHasPassive(creatureList[i], 333) in bc_StartupStatLoss; the outer
 * index is [rsp+0x40] (reset on i == 1). The inner-loop exit now continues the outer loop (byte edit). */
static BYTE e_pumpkin_done[2];
static RValue *hook_e_pumpkin(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue *r; int side;
    if (((CmpEqInt)RVA(0x14028c8f0))((RValue *)(frame + 0x40), 1)) e_pumpkin_done[0] = e_pumpkin_done[1] = 0;
    r = ((GmlScript)RVA(E_HAS_PASSIVE))(self, other, ret, argc, args);
    if (!e_truthy(r, ret) || argc < 1) return r;
    side = e_is_enemy(args[0]);
    if (e_pumpkin_done[side]) { e_set_bool(ret, 0); return ret; }
    e_pumpkin_done[side] = 1;
    return r;
}

/* ---- SU-0158 Valiant Heart: "for each creature with the same secondary Fusion": the ally list no longer includes the
 * creature itself (byte edit), and "no secondary fusion" (-1) never counts as the same. Stands in for the runtime
 * "==" on (ally.fuse2, self.fuse2) in bc_CreatureAttack L813 / bc_CreatureCast L784. */
typedef char (*EqFn)(RValue *a, RValue *b);
static char hook_e_valiant_eq(RValue *a, RValue *b)
{
    CmpEqInt eq_int = (CmpEqInt)RVA(0x14028c8f0);
    if (eq_int(a, -1) || eq_int(b, -1)) return 0;
    return ((EqFn)RVA(E_EQ))(a, b);
}

/* ---- SU-0159 Vicar's Blessing: "this creature has a 35% chance ... This trait does not stack": one 35% roll per
 * event, by the first holder. The per-enemy roll is skipped (byte edit); this stands in for scr_CritHasPassive(e, 1089)
 * in bc_ExecuteEvents L821 (loop index [rsp+0x99f8], reset on i == 1) and makes the single roll itself. */
static BYTE e_vicar_rolled;
static RValue *hook_e_vicar(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *frame = (char *)_AddressOfReturnAddress() + 8;
    RValue *r, chance, *a[1];
    if (((CmpEqInt)RVA(0x14028c8f0))((RValue *)(frame + 0x99f8), 1)) e_vicar_rolled = 0;
    r = ((GmlScript)RVA(E_HAS_PASSIVE))(self, other, ret, argc, args);
    if (!e_truthy(r, ret)) return r;
    if (e_vicar_rolled) { e_set_bool(ret, 0); return ret; }
    e_vicar_rolled = 1;
    memset(&chance, 0, sizeof chance); chance.v.real = 35.0; a[0] = &chance;
    e_set_bool(ret, e_call(E_ROLL, self, other, 1, a));
    return ret;
}
