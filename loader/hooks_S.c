/* Hook batch S: spells and spell-casting traits (see research/hook_batches.json). Included by hooks.c.
 * Every hook stands in for one call at one game site (cave trampoline jmp [slot]); the loader writes the address of
 * the function into the slot named in research/hooks_S.json. Game addresses are 2.0.38 VAs rebased with RVA(). Each
 * hook falls back to the original behaviour when anything is unexpected. */

/* ---- runtime helpers (signatures from their call sites) ---- */
typedef RValue *(*s_Mul3)(RValue *out, RValue *a, RValue *b);        /* 0x140290cc0: out = a * b (temp)      */
typedef RValue *(*s_MulD)(RValue *out, double f, RValue *a);         /* 0x1402e0680: out = a * f (temp)      */
typedef void (*s_AddTo)(RValue *dst, RValue *src);                   /* 0x14028c630: dst += src              */
typedef void (*s_Assign)(RValue *dst, RValue *src);                  /* 0x14028c410: dst = src (refcounted)  */
typedef void (*s_Free)(RValue *v);                                   /* 0x14028c220: release a temp          */
typedef void (*s_AddInt)(RValue *v, int n);                          /* 0x1402f4230: v += n                  */
typedef void (*s_SetInt)(RValue *v, int n);                          /* 0x14028c530: v = n                   */
typedef void (*s_MakeStr)(RValue *out, void *global);                /* 0x14028c360: string value from a global */
typedef char (*s_Cmp2)(RValue *a, RValue *b);                        /* 0x14028c8d0 ==, 0x14028c9e0 >         */
typedef void *(*s_VarSet)(RValue *inst, int var_id, int index, RValue *value, int a5, int a6);

#define S_VAR(slot_va) (*(int *)RVA(slot_va))
#define S_NOIDX ((int)0x80000000)
static const unsigned long long S_SCR_CRITHASPASSIVE = 0x14202c2c0ULL;

/* Result helper: a GML bool/real false. */
static RValue *s_false(RValue *ret) { ret->v.real = 0; ret->flags = 0; ret->kind = 0; return ret; }

/* scr_CritHasPassive(creature, args[0]) in place of a side-wide scr_Any*HasPassive(args[0]). */
static RValue *s_has_passive(RValue *creature, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *a[2];
    if (argc < 1 || !args || !args[0]) return s_false(ret);
    a[0] = creature; a[1] = args[0];
    return ((GmlScript)RVA(S_SCR_CRITHASPASSIVE))(self, other, ret, 2, a);
}

/* ===== SU-0172 Necronomicon: "these spells act as if THIS creature has 50% less Intelligence" =====
 * The three potency calculators test the trait side-wide (scr_AnyAlly/AnyEnemyHasPassive(115)); test the caster.
 * Caster value: bc_SpellDamage [rsp+0xb728]; bc_SpellHealing [rbp-0x50] = rsp+0xb0; bc_SpellStat [rbp-0x40] = rsp+0xc0. */
#define S_CALLER_RSP ((char *)_AddressOfReturnAddress() + 8)
static RValue *hook_su0172_dmg(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0xb728), self, other, ret, argc, args); }
static RValue *hook_su0172_heal(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0xb0), self, other, ret, argc, args); }
static RValue *hook_su0172_stat(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0xc0), self, other, ret, argc, args); }

/* ===== SU-0059 Time Fracture Resonance: "While THIS creature is at the bottom of the Timeline" =====
 * Every site reads the bottom creature (creatureList[count]) and then asks whether ANY creature of its side holds the
 * trait; ask whether the bottom creature itself holds it. Bottom value per site: bc_CreatureCast [rsp+0x305c0],
 * bc_EventDamage [rsp+0x23418], bc_SpellDamage [rsp+0xbcd8], bc_SpellHealing [rbp+0x1a0] = rsp+0x2a0,
 * bc_SpellStat [rbp+0x1b0] = rsp+0x2b0. */
static RValue *hook_su0059_cast(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0x305c0), self, other, ret, argc, args); }
static RValue *hook_su0059_damage(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0x23418), self, other, ret, argc, args); }
static RValue *hook_su0059_spelldmg(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0xbcd8), self, other, ret, argc, args); }
static RValue *hook_su0059_heal(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0x2a0), self, other, ret, argc, args); }
static RValue *hook_su0059_stat(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return s_has_passive((RValue *)(S_CALLER_RSP + 0x2b0), self, other, ret, argc, args); }

/* ===== SU-0021 Creationism: "When your creatures cast a damaging NATURE spell" =====
 * Stands in for scr_CritHasPassive(ally, 480) in bc_SpellDamage L397; true only when the gem's class is Nature
 * (gem value at [rsp+0xb748], the one the Necronomicon class test uses). */
static int s_gem_class_is(RValue *gem, unsigned long long class_global, void *self, void *other)
{
    GmlScript gem_class = (GmlScript)RVA(0x141daadf0);                /* inv_SpellGemClass */
    RValue cls, name, *a[1], *r;
    int same;
    memset(&cls, 0, sizeof cls); memset(&name, 0, sizeof name);
    a[0] = gem;
    r = gem_class(self, other, &cls, 1, a);
    ((s_MakeStr)RVA(0x14028c360))(&name, RVA(class_global));
    same = ((s_Cmp2)RVA(0x14028c8d0))(r ? r : &cls, &name) != 0;
    ((s_Free)RVA(0x14028c220))(&name);
    ((s_Free)RVA(0x14028c220))(&cls);
    return same;
}
static RValue *hook_su0021_creationism(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *gem = (RValue *)(S_CALLER_RSP + 0xb748);
    if (!s_gem_class_is(gem, 0x149d68400ULL /* "Nature" */, self, other)) return s_false(ret);
    return ((GmlScript)RVA(S_SCR_CRITHASPASSIVE))(self, other, ret, argc, args);
}

/* ===== SU-0041 Focused Magicks: "ignore 30% of enemies' Defense, plus 10% more for each creature missing" =====
 * bc_SpellDamage L164-L171 computes Def -= (0.3 x Def) x (0.1 x missing); stand in for that multiply (a = 0.3 x Def,
 * b = 0.1 x missing) and return 0.3 x Def + Def x (0.1 x missing). Def value: [rsp+0xb808]. */
static RValue *hook_su0041_focused(RValue *out, RValue *a, RValue *b)
{
    s_Mul3 mul = (s_Mul3)RVA(0x140290cc0);
    RValue *def = (RValue *)(S_CALLER_RSP + 0xb808);
    RValue *r = mul(out, def, b);                       /* out = Def x (0.1 x missing) */
    ((s_AddTo)RVA(0x14028c630))(r ? r : out, a);       /* += 0.3 x Def */
    return r ? r : out;
}

/* ===== SU-0167 Master of Dumplings: the Dreamsicle skin (code skin 133, Caliban) gets Caliban's Avatar Ultimate =====
 * bc_StartupGems: after the skin -> Ultimate switch, `if (ultimate == -1)` picks a random one; the switch has no case
 * 133. Stand in for that `== -1` test: for skin 133 set the Ultimate to 442 (Awakened Nether Orbs, Caliban's).
 * Skin value: [rsp+0x69f8]; ultimate value: the tested argument ([rsp+0x98]). */
typedef char (*s_EqInt)(RValue *v, int n);
static char hook_su0167_eq(RValue *v, int n)
{
    s_EqInt eq = (s_EqInt)RVA(0x14028c8f0);
    RValue *skin = (RValue *)(S_CALLER_RSP + 0x69f8);
    if (n == -1 && eq(v, -1) && eq(skin, 133)) {
        ((s_SetInt)RVA(0x14028c530))(v, 442);
        return 0;
    }
    return eq(v, n);
}

/* ===== SU-0171 Master of Wolpertingers: "50% chance to be cast 1 additional time. This effect can occur multiple
 * times in a row." Stands in for the `count += 1` (add_int) after the 50% roll in bc_CreatureCast: keep rolling 50%
 * while it succeeds (capped at the per-turn cast limit). self/other of bc_CreatureCast: [rsp+0x42990] / [rsp+0x42998]. */
static void hook_su0171_add(RValue *v, int n)
{
    char *c = S_CALLER_RSP;
    void *self = *(void **)(c + 0x42990), *other = *(void **)(c + 0x42998);
    int extra = 0;
    while (extra < 14 && call_gate((GmlScript)RVA(0x146666e40), self, other, 50.0)) extra++;   /* scr_Roll(50) */
    ((s_AddInt)RVA(0x1402f4230))(v, n + extra);
}

/* ===== SU-0154 Perishing Salvo: "15% of its Intelligence multiplied by the Attack increases granted by its Artifact's
 * Stat Slots". Count every slot that grants Attack (1 and the hybrids 54 / 58 / 59 / 60, as Honed Blades does);
 * no artifact = no increase = 0 (the no-artifact skip is removed by a byte edit). Stands in for
 * inv_ArtifactStatTotal(item, 1) in bc_OnDeath L370. */
static RValue *hook_su0154_total(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript total = (GmlScript)RVA(0x141cef3c0);
    static const double props[] = { 1, 54, 58, 59, 60 };
    double sum = 0;
    int k;
    if (argc < 2 || !args || !args[0]) return total(self, other, ret, argc, args);
    if (!((CmpInt)RVA(0x14028ca10))(args[0], -1)) return s_false(ret);      /* item <= -1: no artifact */
    for (k = 0; k < 5; k++) {
        RValue p, r1, *a[2], *r;
        memset(&p, 0, sizeof p); memset(&r1, 0, sizeof r1);
        p.v.real = props[k];
        a[0] = args[0]; a[1] = &p;
        r = total(self, other, &r1, 2, a);
        if (!r) r = &r1;
        if ((r->kind & 0xffffff) != 0) {                                   /* not a real: give up, original result */
            ((s_Free)RVA(0x14028c220))(&r1);
            return total(self, other, ret, argc, args);
        }
        sum += r->v.real;
    }
    ret->v.real = sum; ret->flags = 0; ret->kind = 0;
    return ret;
}

/* ===== SU-0137 Astral Dimension: "This Spell Gem cannot be Sealed." =====
 * Stands in for the gem.sealed read in bc_CritCanCastSpell (the test that refuses a sealed gem): spell 288 reads as
 * not sealed. The same read also answers "not sealed" for the other gems that cannot be Sealed (SU-0212 Diabolism /
 * Straight Up / Unstoppable Force, SU-0289 Master of Spellmanes; l_gem_unsealable in hooks_L.c, active only when
 * those patches are on). */
static int l_gem_unsealable(RValue *gem);
static void *hook_su0137_sealed(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    RValue sid;
    void *r = varget(inst, var_id, index, out, a5, a6);
    memset(&sid, 0, sizeof sid);
    varget(inst, S_VAR(0x1499e0b28), S_NOIDX, &sid, 0, 0);                /* spellid */
    if (((s_EqInt)RVA(0x14028c8f0))(&sid, 288)) ((s_SetInt)RVA(0x14028c530))(out, 0);
    else if (((ToBool)RVA(0x147871cf0))(out) && l_gem_unsealable(inst)) ((s_SetInt)RVA(0x14028c530))(out, 0);
    return r;
}

/* ===== SU-0139 Corpse Explosion: "a small amount of damage, increased by the number of dead creatures" =====
 * Damage was Moderate x dead count (0 with none dead). A byte edit switches DMG_MODERATE to DMG_SMALL; this stands in
 * for the final multiply (bc_SpellDamage L1684) and uses (dead count + 1). */
static RValue *hook_su0139_mul(RValue *out, RValue *a, RValue *b)
{
    RValue n = *b;                                       /* the dead count: a plain number */
    if ((n.kind & 0xffffff) != 0 && (n.kind & 0xffffff) != 7 && (n.kind & 0xffffff) != 10)
        return ((s_Mul3)RVA(0x140290cc0))(out, a, b);
    ((s_AddInt)RVA(0x1402f4230))(&n, 1);
    return ((s_Mul3)RVA(0x140290cc0))(out, a, &n);
}

/* ===== SU-0011 Shapeshifter card power 2 / 3: "Your creatures take 10% less damage from creatures that are strong
 * against their class" / "Doubles the potency of these effects." The weak-branch code is skipped by a byte edit;
 * this stands in for the strong-branch `amount += bonus` (bc_EventDamage L3949) and then scales amount by 0.9 (0.8
 * with power 3) when the creature hit is yours. self value [rsp+0x21ef8]; self/other [rsp+0x30490] / [rsp+0x30498]. */
static int s_card_power(void *self, void *other, unsigned long long name_global, double power)
{
    GmlScript unlocked = (GmlScript)RVA(0x141cf6e10);                 /* inv_CardSetPowerUnlocked */
    RValue name, p, res, *a[2], *r;
    int on;
    memset(&name, 0, sizeof name); memset(&p, 0, sizeof p); memset(&res, 0, sizeof res);
    ((s_MakeStr)RVA(0x14028c360))(&name, RVA(name_global));
    p.v.real = power;
    a[0] = &name; a[1] = &p;
    r = unlocked(self, other, &res, 2, a);
    on = ((ToBool)RVA(0x147871cf0))(r ? r : &res) != 0;
    ((s_Free)RVA(0x14028c220))(&name);
    return on;
}
static void hook_su0011_add(RValue *dst, RValue *src)
{
    char *c = S_CALLER_RSP;
    void *self = *(void **)(c + 0x30490), *other = *(void **)(c + 0x30498);
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    RValue target, slot, tmp;
    double f = 1.0;
    ((s_AddTo)RVA(0x14028c630))(dst, src);
    memset(&target, 0, sizeof target); memset(&slot, 0, sizeof slot); memset(&tmp, 0, sizeof tmp);
    varget((RValue *)(c + 0x21ef8), S_VAR(0x1499e3228), S_NOIDX, &target, 0, 0);   /* creature (the one hit) */
    varget(&target, S_VAR(0x1499e0aa8), S_NOIDX, &slot, 0, 0);                    /* slot */
    if (!((CmpInt)RVA(0x14028ca10))(&slot, 0)) return;                             /* enemy hit: nothing */
    if (!s_card_power(self, other, 0x149d60f90ULL /* "Shapeshifter" */, 2.0)) return;
    f = s_card_power(self, other, 0x149d60f90ULL, 3.0) ? 0.8 : 0.9;
    {
        RValue *r = ((s_MulD)RVA(0x1402e0680))(&tmp, f, dst);
        ((s_Assign)RVA(0x14028c410))(dst, r ? r : &tmp);
        ((s_Free)RVA(0x14028c220))(&tmp);
    }
}

/* ===== SU-0155 Phasers: "restores 1 charge to a non-Ultimate Spell Gem" — never above the gem's maximum =====
 * Stands in for the gem.charges write after the +1 (bc_EventDamage L5966). */
static void *hook_su0155_set(RValue *inst, int var_id, int index, RValue *value, int a5, int a6)
{
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    RValue mx;
    unsigned k;
    memset(&mx, 0, sizeof mx);
    varget(inst, S_VAR(0x1499e33a8), S_NOIDX, &mx, 0, 0);                         /* charges_max */
    k = mx.kind & 0xffffff;
    if ((k == 0 || k == 7 || k == 10) && ((s_Cmp2)RVA(0x14028c9e0))(value, &mx))  /* value > max */
        ((s_Assign)RVA(0x14028c410))(value, &mx);
    return ((s_VarSet)RVA(0x1478bc260))(inst, var_id, index, value, a5, a6);
}

/* ===== SU-0123 Xyrxzy's Subversion: "After this creature MANUALLY casts a spell" =====
 * bc_OnCast has no manual flag and its block fires after every cast, including its own automatic casts (self-loop to
 * the cast limit). (1) Around the on-cast pass of each execution in bc_CreatureCast, remember whether that cast is
 * manual (argument3 == false, [rsp+0x2fc90], the value the game's own "manual" tests read); (2) the trait's gate in
 * bc_OnCast is false unless the current cast is manual. Nesting-safe: triggered casts set their own flag.
 *
 * SU-0013 Shifting Brilliance / Enochian / Add to the Mix ("a spell of a different class from the LAST spell cast in
 * the current battle") shares this on-cast hook. By the on-cast pass the cast has already written itself into
 * global.last_spell1 (fill 1-3, then shift with last_spell1 = newest), so the three traits compare the spell with
 * itself (from the 4th spell on) or with the battle's first spell (2nd / 3rd). During the pass, last_spell1 holds the
 * previous cast's spell instead, then is put back. Enabled only when the SU-0013 patch is on (its flag slot is filled
 * by the loader); SU-0013 needs SU-0123, which owns the call site. Cells: [rsp+0x16298] = &last_spell1,
 * [rsp+0x16390] = &last_spell2; this cast's spell id: [rsp+0x2fc80]. */
static int s_cast_manual, s_oncast_seen;
static RValue s_last_spell;
static int s_last_valid;
static void hook_su0013_flag(void) {}
#define S_SU0013_ON (*(void **)RVA(0x149ed86a0) != 0)
static int s_is_number(RValue *v) { unsigned k = v->kind & 0xffffff; return k == 0 || k == 7 || k == 10; }
static RValue *hook_su0123_oncast(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *c = S_CALLER_RSP;
    RValue *automatic = (RValue *)(c + 0x2fc90), *cur = (RValue *)(c + 0x2fc80);
    RValue *last1 = *(RValue **)(c + 0x16298), *last2 = *(RValue **)(c + 0x16390);
    int saved_manual = s_cast_manual, swapped = 0;
    RValue saved1, prev;
    memset(&saved1, 0, sizeof saved1); memset(&prev, 0, sizeof prev);
    RValue *r;
    s_oncast_seen = 1;
    s_cast_manual = ((ToBool)RVA(0x147871cf0))(automatic) == 0;
    if (S_SU0013_ON && last1 && last2 && s_is_number(cur) && s_is_number(last1)) {
        if (((s_EqInt)RVA(0x14028c8f0))(last2, -1) && ((s_Cmp2)RVA(0x14028c8d0))(last1, cur))
            s_last_valid = 0;                                  /* first spell of the battle: nothing before it */
        if (s_last_valid) { saved1 = *last1; prev = s_last_spell; *last1 = prev; swapped = 1; }
        s_last_spell = *cur; s_last_valid = 1;                 /* before the pass: nested casts see this one */
    }
    r = ((GmlScript)RVA(0x14107f780))(self, other, ret, argc, args);              /* bc_EventOnCast */
    if (swapped && memcmp(last1, &prev, sizeof prev) == 0) *last1 = saved1;       /* untouched by nested casts */
    s_cast_manual = saved_manual;
    return r;
}
static RValue *hook_su0123_gate(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    if (s_oncast_seen && !s_cast_manual) return s_false(ret);
    return ((GmlScript)RVA(S_SCR_CRITHASPASSIVE))(self, other, ret, argc, args);
}

/* ===== SU-0017 Incoming Tide: "At the start of this creature's turn, it has a 50% chance to cast Submerge." =====
 * The statement is empty in the game (bc_CreatureStartOfTurn L4159). Stands in for its scr_CritHasPassive(creature,
 * 1660) test: when true, roll 50% and cast Submerge (spell 551) the way the neighbouring trait at L4153-L4156 casts
 * its spell: inv_CreateSpellGem(spell) then bc_CreatureCastSpellGem(creature, gem, automatic = true). */
static RValue *hook_su0017_tide(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(S_SCR_CRITHASPASSIVE))(self, other, ret, argc, args);
    if (argc >= 1 && args && args[0] && ((ToBool)RVA(0x147871cf0))(r ? r : ret)
        && call_gate((GmlScript)RVA(0x146666e40), self, other, 50.0)) {                 /* scr_Roll(50) */
        RValue sid, gem, res, *a1[1], *a3[3], *g;
        memset(&sid, 0, sizeof sid); memset(&gem, 0, sizeof gem); memset(&res, 0, sizeof res);
        sid.v.real = 551;
        a1[0] = &sid;
        g = ((GmlScript)RVA(0x141d03e30))(self, other, &gem, 1, a1);                  /* inv_CreateSpellGem */
        a3[0] = args[0]; a3[1] = g ? g : &gem; a3[2] = (RValue *)RVA(0x1498e0f60);    /* static true */
        ((GmlScript)RVA(0x140aab480))(self, other, &res, 3, a3);                      /* bc_CreatureCastSpellGem */
        ((s_Free)RVA(0x14028c220))(&res);
        ((s_Free)RVA(0x14028c220))(&gem);
    }
    return r;
}
