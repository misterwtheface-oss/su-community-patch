/* Hook batch F2 (round 3, structural; see research/hook_batches.json and research/build_hooks_F2.py).
 * Included by hooks.c after the round-1/2 batch files. */

#define F2_PERKLEVEL      0x1464eb110
#define F2_ANYALLY        0x141f0a8a0
#define F2_ANYENEMY       0x141f0b2d0
#define F2_ALLRACE        0x140601da0
#define F2_CRITRELICPERK  0x14202d600
#define F2_BATTLETYPE     0x141f1f3f0
#define F2_ONDEATH        0x141462dc0
#define F2_STATIC_SIDE    0x1498e0f50       /* the static second argument the game passes to scr_PerkLevel */
#define F2_STATIC_TRUE    0x1498e0f60       /* static bool true */
#define F2_RIFTDANCER_STR 0x149d63410       /* global holding the "Rift Dancer" race string */

static RValue *f2_real(RValue *v, double d) { memset(v, 0, sizeof *v); v->v.real = d; return v; }

/* scr_PerkLevel(id, <game's static side arg>) > 0, as the bc_OnDeath / bc_HandleDeath gates call it. */
static int f2_perk(void *self, void *other, double id)
{
    RValue a, res, *args[2], *r;
    memset(&res, 0, sizeof res);
    args[0] = f2_real(&a, id);
    args[1] = (RValue *)RVA(F2_STATIC_SIDE);
    r = ((GmlScript)RVA(F2_PERKLEVEL))(self, other, &res, 2, args);
    return ((CmpInt)RVA(0x14028ca10))(r ? r : &res, 0) != 0;
}

/* ===== SU-0108 True Ending: "Effects that activate when creatures die are ignored. This perk does not affect Born
 * Again." The game's exit (bc_OnDeath L162: scr_PerkLevel(448) > 0 && the boss flag is false) comes after the
 * blocks at L16-L158, so those still ran. The boss flag is set at L80 from scr_BattleType(arg) == 1.
 * This stands in for the temp release at the end of L14 (runs on every death, after setup): it decides whether True
 * Ending applies exactly as L80 + L162 will; the frameless detours at L16 / L84 / L95 then jump L16 -> L80 (the game
 * still sets its boss flag), L84 -> L90 (Born Again), L95 -> L162 (the game's own True Ending exit). */
typedef void *(*Release)(RValue *v);
static void *hook_su0108_l14(RValue *v)
{
    void *r = ((Release)RVA(0x14028c220))(v);
    char *c = (char *)_AddressOfReturnAddress() + 8;          /* bc_OnDeath's frame */
    void *self = *(void **)(c + 0x15050), *other = *(void **)(c + 0x15058);
    RValue *arg = *(RValue **)(c + 0x5ab0);
    BYTE *flag = RVA(0x149ed8560);
    int te = 0;
    if (arg && f2_perk(self, other, 448.0)) {
        RValue bt, *pb;
        memset(&bt, 0, sizeof bt);
        pb = ((GmlScript)RVA(F2_BATTLETYPE))(self, other, &bt, 1, &arg);
        te = !((CmpEqInt)RVA(0x14028c8f0))(pb ? pb : &bt, 1);   /* not a boss battle */
    }
    *flag = (BYTE)te;
    return r;
}

/* ===== SU-0024 Demonologist vs anointed Undying Loyalty / Eternal Guardian (bc_HandleDeath).
 * The condition chain is "first match wins": Demonologist (L91, keep only the 7 demon minions 56-62) comes before
 * Undying Loyalty (L107, perk 231: "minions persist", removes buffs + debuffs) and Eternal Guardian (L117, perk 387:
 * "buffs persist", removes debuffs + minions), so anointed UL / EG did nothing for a Demonologist. Also, with UL and EG
 * together UL won and buffs were lost. Now each keeps what its text keeps:
 *   - L91's playertype == 35 compare reports "not Demonologist" when UL or EG applies (the chain moves on);
 *   - UL's IsBuff test is false when EG also applies (buffs kept);
 *   - EG's IsMinion test is false for the demon minions when the spec is Demonologist (demons kept).
 * self / other live in r13 / r15 at the L91 compare; the trampoline saves them to 0x149ed8570 / 0x149ed8578. */
typedef int (*ValCmp)(RValue *a, RValue *b, double eps, int mode);
static int hook_su0024_demon(RValue *a, RValue *b, double eps, int mode)
{
    int r = ((ValCmp)RVA(0x1478a6470))(a, b, eps, mode);      /* 0 = equal: Demonologist */
    void *self = *(void **)RVA(0x149ed8570), *other = *(void **)RVA(0x149ed8578);
    *RVA(0x149ed8580) = (BYTE)(r == 0);
    if (r == 0 && (f2_perk(self, other, 231.0) || f2_perk(self, other, 387.0)))
        return 1;                                             /* skip the Demonologist step */
    return r;
}
static RValue *hook_su0024_isbuff(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(0x141fa4c50))(self, other, ret, argc, args);      /* scr_ConditionIsBuff */
    if (((ToBool)RVA(0x147871cf0))(r ? r : ret) && f2_perk(self, other, 387.0)) {
        ret->v.real = 0; ret->flags = 0; ret->kind = 0;
        return ret;
    }
    return r;
}
static RValue *hook_su0024_isminion(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(0x141fa5610))(self, other, ret, argc, args);      /* scr_ConditionIsMinion */
    if (*RVA(0x149ed8580) && argc >= 1 && args && args[0] && ((ToBool)RVA(0x147871cf0))(r ? r : ret)) {
        int id;
        for (id = 56; id <= 62; id++)
            if (((CmpEqInt)RVA(0x14028c8f0))(args[0], id)) {
                ret->v.real = 0; ret->flags = 0; ret->kind = 0;
                return ret;
            }
    }
    return r;
}

/* ===== SU-0046 Master of Rift Dancers on deaths: "If all the creatures in your party are Rift Dancers, their innate
 * traits are 100% more effective / activate 1 additional time." The Rift Dancers' death innate is Dark Dance (50):
 * "All effects that activate when a creature dies will activate 1 additional time". So the master's extra pass is
 * Dark Dance activating once more: it needs Dark Dance on the master's side (as the Defend / Provoke cases already
 * nest Master of Rift Dancers inside Fan Dance / Moon Dance). The game's count (bc_ExecuteEvents L448) adds the pass
 * for a side holding 1481 whose creatures are all Rift Dancers. These stand in for its two bc_AllRace calls (enemy
 * side, your side) and also require that side to hold Dark Dance. */
static int f2_side_has(void *self, void *other, int your_side, double id)
{
    return call_gate((GmlScript)RVA(your_side ? F2_ANYALLY : F2_ANYENEMY), self, other, id);
}
static RValue *f2_allrace_dark(void *self, void *other, RValue *ret, int argc, RValue **args, int your_side)
{
    RValue *r = ((GmlScript)RVA(F2_ALLRACE))(self, other, ret, argc, args);
    if (((ToBool)RVA(0x147871cf0))(r ? r : ret) && !f2_side_has(self, other, your_side, 50.0)) {
        ret->v.real = 0; ret->flags = 0; ret->kind = 0;
        return ret;
    }
    return r;
}
static RValue *hook_su0046_enemy(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return f2_allrace_dark(self, other, ret, argc, args, 0); }
static RValue *hook_su0046_ally(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return f2_allrace_dark(self, other, ret, argc, args, 1); }

/* Master of Rift Dancers' extra death pass, computed the same way (side holds 1481, all Rift Dancers, Dark Dance). */
static int f2_rift_master(void *self, void *other)
{
    int side;
    for (side = 0; side <= 1; side++) {
        RValue sv, res, *args[2], *r;
        if (!f2_side_has(self, other, side, 1481.0) || !f2_side_has(self, other, side, 50.0)) continue;
        memset(&res, 0, sizeof res);
        args[0] = (RValue *)RVA(F2_RIFTDANCER_STR);
        args[1] = f2_real(&sv, side ? 1.0 : 0.0);
        r = ((GmlScript)RVA(F2_ALLRACE))(self, other, &res, 2, args);
        if (((ToBool)RVA(0x147871cf0))(r ? r : &res)) return 1;
    }
    return 0;
}

/* ===== SU-0025 instant kills: damage deaths repeat bc_OnDeath for Fable rank 80 ("the bearer's on-death effects
 * activate 1 additional time") and Master of Rift Dancers; the instant-kill path (bc_ExecuteEvents L986-L1000) adds
 * only Defiance, Dark Dance and Illusion. This stands in for its base bc_OnDeath call (L986, runs once per instant
 * kill): after it, one more pass for a Fable 80 bearer (relic 29, perk 8, dead bearer allowed, as SU-0008) and one
 * more when Master of Rift Dancers applies. */
static RValue *hook_su0025_ohko(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript ondeath = (GmlScript)RVA(F2_ONDEATH);
    RValue *r = ondeath(self, other, ret, argc, args);
    if (argc >= 2 && args && args[1]) {
        RValue a29, a8, res, *ra[4], *rr;
        memset(&res, 0, sizeof res);
        ra[0] = args[1]; ra[1] = f2_real(&a29, 29.0); ra[2] = f2_real(&a8, 8.0); ra[3] = (RValue *)RVA(F2_STATIC_TRUE);
        rr = ((GmlScript)RVA(F2_CRITRELICPERK))(self, other, &res, 4, ra);
        if (((ToBool)RVA(0x147871cf0))(rr ? rr : &res)) r = ondeath(self, other, ret, argc, args);
        if (f2_rift_master(self, other)) r = ondeath(self, other, ret, argc, args);
    }
    return r;
}
