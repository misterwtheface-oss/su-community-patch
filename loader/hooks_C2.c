/* Hook batch C2 (round 2; see research/hook_batches.json). Included by hooks.c after the round-1 files. */

/* ===== SU-0050 Gambler's Game: "At the start of each creature's turn, it has a 50% chance to gain a random buff.
 * Otherwise, it gains a random trait." The else branch (bc_CreatureStartOfTurn L3667-L3668) queued a random DEBUFF.
 * Stands in for its bc_EventDebuff(source, creature, debuff, duration, p1, p2, p3, color, label) call and returns a
 * trait event instead, built the way the game's own random-trait grant builds it (bc_CreatureStartOfTurn L615-L620,
 * same shape in bc_OnResurrect): p = scr_GetRandomPassive() rerolled while p < 0, then
 * bc_EventTrait(-1, creature, p, true, true, label). The returned event goes to the same scr_AddEventToStack call. */
static RValue *hook_su0050_gambler(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x140fdb040);            /* bc_EventDebuff */
    GmlScript rand_passive = (GmlScript)RVA(0x146175fa0);    /* scr_GetRandomPassive() */
    GmlScript event_trait = (GmlScript)RVA(0x141085440);     /* bc_EventTrait */
    CmpInt less_int = (CmpInt)RVA(0x140290d30);              /* runtime "value < int" */
    RValue p, *pr, src, *ta[6];
    int tries;
    if (argc < 9 || !args || !args[1] || !args[8]) return orig(self, other, ret, argc, args);   /* unexpected: as before */
    memset(&p, 0, sizeof p);
    for (tries = 0; tries < 64; tries++) {
        pr = rand_passive(self, other, &p, 0, NULL);
        if (pr && pr != &p) p = *pr;
        if (!less_int(&p, 0)) break;
    }
    if (tries == 64) return orig(self, other, ret, argc, args);
    memset(&src, 0, sizeof src); src.v.real = -1.0;
    ta[0] = &src;                                         /* source -1, as the game's own grant */
    ta[1] = args[1];                                      /* creature */
    ta[2] = &p;                                           /* the trait */
    ta[3] = (RValue *)RVA(0x1498e0f60);                   /* static bool true (read-only use) */
    ta[4] = (RValue *)RVA(0x1498e0f60);
    ta[5] = args[8];                                      /* the block's own label */
    return event_trait(self, other, ret, 6, ta);
}

/* ===== SU-0028 (remainder) Master of Cataclysms: "If all the creatures in your party are Cataclysms, their traits
 * have a 10% chance to activate at the start of each creatures' turn as well." The gate (bc_CreatureStartOfTurn
 * L748-L749) ran the sweep only on turns of the master's own side. Now: a side qualifies when it holds Master of
 * Cataclysms (2191) and its whole party is Cataclysm (bc_AllRace("Cataclysm", side), side 1 = yours, 0 = enemy);
 * the four gate calls (two scr_Any*HasPassive, two bc_AllRace) answer "some side qualifies", so the sweep runs on
 * every creature's turn, and the holder filter (the batch-E sweep hook's slot, refilled with c2_cataclysm_holder
 * when this patch is on; needs SU-0028) lets a Wrath trait roll only when its holder's side qualifies.
 * The result depends only on the battle state, not on whose turn it is, so nesting is harmless. */
static int c2_cata_mask;                                  /* bit0 = your side qualifies, bit1 = enemy side */
static int c2_side_qualifies(void *self, void *other, int player_side)
{
    RValue id, side, res, *a1[1], *a2[2], *r;
    memset(&id, 0, sizeof id); id.v.real = 2191.0;
    a1[0] = &id;
    memset(&res, 0, sizeof res);
    r = ((GmlScript)RVA(player_side ? 0x141f0a8a0 : 0x141f0b2d0))(self, other, &res, 1, a1);
    if (!((ToBool)RVA(0x147871cf0))(r ? r : &res)) return 0;
    memset(&side, 0, sizeof side); side.v.real = player_side ? 1.0 : 0.0;
    a2[0] = (RValue *)RVA(0x149d5f130);                   /* the game's "Cataclysm" string value (read-only) */
    a2[1] = &side;
    memset(&res, 0, sizeof res);
    r = ((GmlScript)RVA(0x140601da0))(self, other, &res, 2, a2);      /* bc_AllRace */
    return ((ToBool)RVA(0x147871cf0))(r ? r : &res) != 0;
}
static RValue *hook_su0028_cata_gate(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    (void)argc; (void)args;
    c2_cata_mask = (c2_side_qualifies(self, other, 1) ? 1 : 0) | (c2_side_qualifies(self, other, 0) ? 2 : 0);
    ret->v.real = c2_cata_mask ? 1.0 : 0.0; ret->flags = 0; ret->kind = 0;
    return ret;
}
static RValue *c2_cataclysm_holder(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    if (argc >= 1 && args && args[0]) {
        int enemy = e_is_enemy(args[0]);
        if (!(c2_cata_mask & (enemy ? 2 : 1))) { e_set_bool(ret, 0); return ret; }
    }
    return ((GmlScript)RVA(E_HAS_PASSIVE))(self, other, ret, argc, args);
}
