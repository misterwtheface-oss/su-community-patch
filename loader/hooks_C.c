/* Hook batch C: combat engine (see research/build_hooks_C.py for the game-side edits of each hook).
 * Every hook stands in for exactly one call and has the callee's signature. Included by hooks.c. */

/* ---- helpers ---------------------------------------------------------------------------------------------- */
static void c_real(RValue *v, double d) { memset(v, 0, sizeof *v); v->v.real = d; }

/* Run a GML script and convert its result with the runtime's own bool conversion. */
static int c_script_bool(GmlScript fn, void *self, void *other, int argc, RValue **args)
{
    ToBool to_bool = (ToBool)RVA(0x147871cf0);
    RValue res, *r;
    memset(&res, 0, sizeof res);
    r = fn(self, other, &res, argc, args);
    return to_bool(r ? r : &res) != 0;
}

/* inst.var into out (out zeroed first). */
static void c_get(RValue *inst, unsigned long long slot_va, RValue *out)
{
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    memset(out, 0, sizeof *out);
    varget(inst, *(int *)RVA(slot_va), (int)0x80000000, out, 0, 0);
}

#define C_SLOT_SOURCE 0x1499e0c38
#define C_SLOT_SLOTV  0x1499e0aa8      /* creature.slot: 0 = enemy side, > 0 = your side */
#define C_SLOT_HP     0x1499e0a88
#define C_SCR_ROLL               0x146666e40
#define C_SCR_CRITHASCONDITION   0x14202b010
#define C_SCR_CRITHASPASSIVE     0x14202c2c0

static int c_gt_int(RValue *v, int n) { return ((CmpInt)RVA(0x14028ca10))(v, n) != 0; }

static RValue *c_ret_false(RValue *ret) { memset(ret, 0, sizeof *ret); return ret; }   /* real 0 = false */

/* ---- SU-0115 No Head Necessary ---------------------------------------------------------------------------- */
/* "While this creature is dead, it has a 50% chance to attack enemies at the start of their turns."
 * bc_CreatureStartOfTurn L5076 made one 50% roll for all dead holders (now always passes); this stands in for the
 * L5080 bc_CreatureAttack call (one per dead holder) and rolls 50% for that holder. */
static RValue *hook_su0115_attack(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue fifty, *a[1];
    c_real(&fifty, 50.0); a[0] = &fifty;
    if (!c_script_bool((GmlScript)RVA(C_SCR_ROLL), self, other, 1, a))
        return ret;                                        /* this holder's roll failed: no attack */
    return ((GmlScript)RVA(0x14069c200))(self, other, ret, argc, args);   /* bc_CreatureAttack */
}

/* ---- SU-0148 Colony ----------------------------------------------------------------------------------------- */
/* "After one of your other Griffons defend, the rest of them defend as well." The bc_OnDefend L442-L456 loop made
 * dead Griffons Defend too. Stands in for its bc_CreatureDefend(griffon, 1): only living Griffons defend. */
static RValue *hook_su0148_defend(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue hp;
    if (argc < 1) return ret;
    c_get(args[0], C_SLOT_HP, &hp);
    if (!c_gt_int(&hp, 0)) return ret;
    return ((GmlScript)RVA(0x140ab0390))(self, other, ret, argc, args);   /* bc_CreatureDefend */
}

/* ---- SU-0161 Greybeard's Blessing --------------------------------------------------------------------------- */
/* "Your creatures grant 100% more healing to enemies with Blighted." bc_EventHeal tested only the healed creature
 * (Blighted, opposing side) and never the healer, so every heal on it was doubled (its own heals, Mending...).
 * These stand in for the two side gates; they also require the heal's source to be on the holder's side.
 * bc_EventHeal's self value (the heal event) is at [caller rsp + 0x50]. */
static RValue *c_greybeard(void *self, void *other, RValue *ret, int argc, RValue **args,
                           unsigned long long gate, char *caller_rsp, int holder_is_enemy_side)
{
    RValue src, side;
    RValue *r = ((GmlScript)RVA(gate))(self, other, ret, argc, args);
    ToBool to_bool = (ToBool)RVA(0x147871cf0);
    if (!to_bool(r ? r : ret)) return r;
    c_get((RValue *)(caller_rsp + 0x50), C_SLOT_SOURCE, &src);
    if (!c_gt_int(&src, -1)) return c_ret_false(ret);      /* sourceless (Mending etc.): not "your creatures" */
    c_get(&src, C_SLOT_SLOTV, &side);
    if (holder_is_enemy_side ? c_gt_int(&side, 0) : !c_gt_int(&side, 0))
        return c_ret_false(ret);                           /* healer is not on the holder's side */
    return r;
}
static RValue *hook_su0161_enemy_gate(void *self, void *other, RValue *ret, int argc, RValue **args)
{   /* healed creature is yours (slot > 0): holder on the enemy side -> healer must be an enemy */
    return c_greybeard(self, other, ret, argc, args, 0x141f0b2d0, (char *)_AddressOfReturnAddress() + 8, 1);
}
static RValue *hook_su0161_ally_gate(void *self, void *other, RValue *ret, int argc, RValue **args)
{   /* healed creature is an enemy (slot 0): holder on your side -> healer must be yours */
    return c_greybeard(self, other, ret, argc, args, 0x141f0a8a0, (char *)_AddressOfReturnAddress() + 8, 0);
}

/* ---- SU-0016 Celestial Nexus -------------------------------------------------------------------------------- */
/* "While this creature has Barrier or Shell, it takes damage from attacks and spells in place of your other
 * creatures." bc_EventDamage L395 tested Barrier / Shell on the creature that was hit (now always passes); this
 * stands in for the L398 scr_CritHasPassive(ally, 1710) holder test and also requires the holder's Barrier / Shell. */
static RValue *hook_su0016_nexus_holder(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript has_cond = (GmlScript)RVA(C_SCR_CRITHASCONDITION);
    RValue *r = ((GmlScript)RVA(C_SCR_CRITHASPASSIVE))(self, other, ret, argc, args);
    ToBool to_bool = (ToBool)RVA(0x147871cf0);
    RValue cond, *a[2];
    if (argc < 1 || !to_bool(r ? r : ret)) return r;
    a[0] = args[0]; a[1] = &cond;
    c_real(&cond, 6.0);                                    /* Barrier */
    if (c_script_bool(has_cond, self, other, 2, a)) return r;
    c_real(&cond, 13.0);                                   /* Shelled */
    if (c_script_bool(has_cond, self, other, 2, a)) return r;
    return c_ret_false(ret);
}

/* ---- SU-0165 Kiichi's Persistence ---------------------------------------------------------------------------- */
/* "Enemies with Bleeding take this damage an additional time at the end of their turn. This damage is not modified
 * by traits and other effects that affect Bleeding." The extra hit (bc_CreatureEndOfTurn) recomputes Bleed with
 * bc_CalculateBleedDamage, which applies every Bleed modifier (Master of Pilwizes, traits 1304 / 1305 / 2192 / 2045,
 * the Pilwiz card powers, the relic rank). While that one call runs, the modifier gates inside report false, so the
 * extra hit is the base Bleed amount. Normal Bleed ticks are untouched. Nesting-safe counter. */
static int g_su0165_raw;
static RValue *hook_su0165_bleed(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r;
    g_su0165_raw++;
    r = ((GmlScript)RVA(0x140671f30))(self, other, ret, argc, args);          /* bc_CalculateBleedDamage */
    g_su0165_raw--;
    return r;
}
static RValue *c_su0165_gate(unsigned long long fn, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    if (g_su0165_raw) return c_ret_false(ret);
    return ((GmlScript)RVA(fn))(self, other, ret, argc, args);
}
static RValue *hook_su0165_any_ally(void *s, void *o, RValue *r, int c, RValue **a) { return c_su0165_gate(0x141f0a8a0, s, o, r, c, a); }
static RValue *hook_su0165_any_enemy(void *s, void *o, RValue *r, int c, RValue **a) { return c_su0165_gate(0x141f0b2d0, s, o, r, c, a); }
static RValue *hook_su0165_card(void *s, void *o, RValue *r, int c, RValue **a) { return c_su0165_gate(0x141cf6e10, s, o, r, c, a); }
static RValue *hook_su0165_relic(void *s, void *o, RValue *r, int c, RValue **a) { return c_su0165_gate(0x14202d600, s, o, r, c, a); }

/* ---- SU-0023 Book of the Arsonist --------------------------------------------------------------------------- */
/* "Enemies' Burned debuffs applied by this creature also deal 30% more damage." bc_EventDebuff L246 scaled p1 of
 * every debuff the holder applied. Stands in for the L246 scr_CritHasPassive(source, 404) gate and also requires the
 * debuff to be Burned (18) and its target to be on the other side. The debuff event (self) is at [caller rsp + 0x50];
 * its condition field is 0x1499347e8 (set from argument 2 at L17). */
static RValue *hook_su0023_arsonist(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    RValue *ev = (RValue *)(caller_rsp + 0x50);
    RValue *r = ((GmlScript)RVA(C_SCR_CRITHASPASSIVE))(self, other, ret, argc, args);
    ToBool to_bool = (ToBool)RVA(0x147871cf0);
    RValue cond, src, tgt, s1, s2;
    if (!to_bool(r ? r : ret)) return r;
    c_get(ev, 0x1499347e8, &cond);
    if (!((CmpEqInt)RVA(0x14028c8f0))(&cond, 18)) return c_ret_false(ret);   /* not Burned */
    c_get(ev, C_SLOT_SOURCE, &src); c_get(ev, 0x1499e3228, &tgt);
    c_get(&src, C_SLOT_SLOTV, &s1); c_get(&tgt, C_SLOT_SLOTV, &s2);
    if (c_gt_int(&s1, 0) == c_gt_int(&s2, 0)) return c_ret_false(ret);      /* not an enemy of the holder */
    return r;
}

/* ---- SU-0047 death flags on a living creature --------------------------------------------------------------- */
/* On-death effects that run without a death (Mortal Terror, Anger Management, Afterlife, Feign Death) run the whole
 * bc_OnDeath on a living creature, and its death-flag blocks then mark it "cannot be resurrected" (e.g. Feast and
 * Famine: "Enemies that die with Fear cannot be resurrected"). Stands in for the five `can_resurrect = false`
 * writes (Epigraphy, End On a High Note, Feast and Famine, Burn Their Corpses, Endwalker): write only if the creature
 * is actually dead (hp <= 0). */
typedef void *(*C_VarSet)(RValue *inst, int var_id, int index, RValue *value);
static void *hook_su0047_deathflag(RValue *inst, int var_id, int index, RValue *value)
{
    RValue hp;
    c_get(inst, C_SLOT_HP, &hp);
    if (c_gt_int(&hp, 0)) return 0;                        /* still alive: no death flag */
    return ((C_VarSet)RVA(0x1478bc260))(inst, var_id, index, value);
}

/* ---- SU-0057 Details Matter --------------------------------------------------------------------------------- */
/* "Your creatures always take damage as if they are strong against their enemy's class." bc_EventDamage L4006-L4007
 * halved the hit after the class step, whatever that step had done (a hit the attacker was strong on ended at x1, a
 * weak one at x0.25). Stands in for the L4006 big_mult(amount, 0.5): the cut now brings the hit to half of a neutral
 * hit (the 'defender strong' result): attacker strong (x2) -> keep 0.25, neutral -> 0.5, already weak (x0.5) -> 1.
 * L4008 still marks the hit as weak (so Capitalize / Judgment Day don't fire), which is what "as if strong" means.
 * Strong-hit variants other than x2 (e.g. Master of Unguided) are treated as x2. */
static RValue *hook_su0057_details(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    RValue strength, f, *a[2];
    CmpEqInt eq = (CmpEqInt)RVA(0x14028c8f0);
    double cut = 0.5;                                      /* amount -= amount x cut */
    if (argc >= 2) {
        c_get((RValue *)(caller_rsp + 0x21ef8), 0x1499c8598, &strength);   /* 1 strong, 0 weak, -1 neutral */
        if (eq(&strength, 1)) cut = 0.75;
        else if (eq(&strength, 0)) cut = 0.0;
        c_real(&f, cut); a[0] = args[0]; a[1] = &f;
        return ((GmlScript)RVA(0x1417a2e70))(self, other, ret, 2, a);       /* big_mult */
    }
    return ((GmlScript)RVA(0x1417a2e70))(self, other, ret, argc, args);
}

/* ---- SU-0147 Braze / SU-0058 Unbreakable -------------------------------------------------------------------- */
/* Braze: "Your creatures' Class Strength Artifact properties deal 50% more damage to that class."
 * Unbreakable: "... prevent 50% more damage from that class."
 * In each of the five per-class blocks the game computes the property's own term with big_mult(amount, stat / 100)
 * (Braze L4039 ... / Unbreakable L1818 ...), then the trait adds a flat amount x 0.5, ignoring the property. The first
 * hook records the property term; the second replaces the flat amount with that term (so the trait adds 50% of
 * what the property does; no property, nothing). Separate state per trait. */
typedef RValue *(*C_MulD)(RValue *out, RValue *in, double f);
static RValue g_su0147_term, g_su0058_term;
static int g_su0147_ok, g_su0058_ok;
static RValue *c_term_capture(RValue *term, int *ok, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(0x1417a2e70))(self, other, ret, argc, args);    /* big_mult */
    RValue *v = r ? r : ret;
    *ok = ((v->kind & 0xffffff) == 0);                     /* a real number */
    if (*ok) c_real(term, v->v.real);
    return r;
}
static RValue *c_term_use(RValue *term, int *ok, RValue *out, RValue *in, double f)
{
    RValue z;
    (void)in;
    if (*ok) { *ok = 0; return ((C_MulD)RVA(0x1402e05e0))(out, term, f); }
    c_real(&z, 0.0);
    return ((C_MulD)RVA(0x1402e05e0))(out, &z, f);
}
static RValue *hook_su0147_term(void *s, void *o, RValue *r, int c, RValue **a) { return c_term_capture(&g_su0147_term, &g_su0147_ok, s, o, r, c, a); }
static RValue *hook_su0147_braze(RValue *out, RValue *in, double f) { return c_term_use(&g_su0147_term, &g_su0147_ok, out, in, f); }
static RValue *hook_su0058_term(void *s, void *o, RValue *r, int c, RValue **a) { return c_term_capture(&g_su0058_term, &g_su0058_ok, s, o, r, c, a); }
static RValue *hook_su0058_unbreakable(RValue *out, RValue *in, double f) { return c_term_use(&g_su0058_term, &g_su0058_ok, out, in, f); }

/* ---- SU-0149 Diabolic Link ---------------------------------------------------------------------------------- */
/* "At the start of battle, your Diabolic Horde share their Maximum Health with each other. Then, their Maximum Health
 * is decreased by 75%." bc_StartupStatGain sums every Diabolic's Max Health including its own (L1463-L1467), then
 * adds that whole total to each one's Max Health and Health (L1474 / L1475), so its own share counted twice (a lone
 * Diabolic ended at 50%). Stand-ins for those two `+= total` adds: Max Health becomes the total (own + the others');
 * Health grows by total - own Max Health (the others' share). */
typedef RValue *(*C_Op2)(RValue *dst, RValue *src);
static RValue g_su0149_own;
static RValue *hook_su0149_max(RValue *dst, RValue *total)
{
    c_real(&g_su0149_own, 0.0);
    ((C_Op2)RVA(0x14028c630))(&g_su0149_own, dst);         /* own = 0 + Max Health (numeric copy) */
    return ((C_Op2)RVA(0x14028c410))(dst, total);          /* Max Health = total */
}
static RValue *hook_su0149_hp(RValue *dst, RValue *total)
{
    RValue d;
    c_real(&d, 0.0);
    ((C_Op2)RVA(0x14028c630))(&d, total);                  /* d = total */
    ((C_Op2)RVA(0x140290910))(&d, &g_su0149_own);          /* d -= own Max Health */
    return ((C_Op2)RVA(0x14028c630))(dst, &d);             /* Health += d */
}

/* ---- SU-0160 Grandiose ------------------------------------------------------------------------------------------ */
/* "At the end of your creatures' turns, their turn counter increases by 3." bc_CreatureStartOfTurn L93-L94 added the 3
 * at the start of the turn (that block is now skipped). Stands in for each regular bc_CreatureEndOfTurn call (all its
 * call sites pair with a bc_CreatureStartOfTurn call; its own recursive call for adjacent creatures is not hooked):
 * the same AnyAllyHasPassive(1982) test with the call's self/other, then global.creature.battleturns += 3, then the
 * original end of turn. */
static RValue *hook_su0160_end_of_turn(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    typedef RValue *(*C_GlobalVar)(void *globals, int var_id);
    RValue id, bt, three, *a[1], *turn;
    c_real(&id, 1982.0); a[0] = &id;
    if (c_script_bool((GmlScript)RVA(0x141f0a8a0), self, other, 1, a)) {            /* scr_AnyAllyHasPassive */
        turn = ((C_GlobalVar)RVA(0x140297c10))(*(void **)RVA(0x1499f57c8), *(int *)RVA(0x1499e1f18));   /* global.creature */
        if (turn) {
            c_get(turn, 0x1499e17e8, &bt);                                          /* battleturns */
            c_real(&three, 3.0);
            ((C_Op2)RVA(0x14028c630))(&bt, &three);
            ((C_VarSet)RVA(0x1478bc260))(turn, *(int *)RVA(0x1499e17e8), (int)0x80000000, &bt);
        }
    }
    return ((GmlScript)RVA(0x140ab2ad0))(self, other, ret, argc, args);             /* bc_CreatureEndOfTurn */
}
