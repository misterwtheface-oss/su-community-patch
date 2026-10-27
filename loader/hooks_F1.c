/* Hook batch F1 (round 3; see research/hook_batches.json): Unrealized Potential, Sugar Rush, Careful What You Wish
 * For / Grim Ailment, Master of Stags x Christmas Is Canceled. (Master of Revenants and Puppet Master are pure byte
 * edits.) Included by hooks.c after all earlier batch files; reuses RValue / GmlScript / VarGet / RVA / CmpInt /
 * CmpEqInt / ToBool (hooks.c), a2_num / a2_set_real (hooks_A2.c), e_var / e_is_enemy / e_call / e_side_has /
 * e_truthy (hooks_E.c) and b2_stags (hooks_B2.c). Every hook keeps the exact signature of the callee it stands in for
 * and falls back to the original behaviour when anything is unexpected. Built by research/build_hooks_F1.py. */

#define F1_VARGET        0x1478bbd70
#define F1_ADD_CONDITION 0x142015940   /* scr_CritAddCondition(creature, condition, duration, ...) */
#define F1_REMOVE_COND   0x14203dbf0   /* scr_CritRemoveCondition(creature, condition) */
#define F1_IS_DEBUFF     0x141fa5120   /* scr_ConditionIsDebuff(condition) */
#define F1_ARR_GET       0x14028c820   /* runtime: RValue *element(RValue *array, int index) */
#define F1_IRANDOM       0x1478b83e0   /* irandom_range(lo, hi) on 64-bit ints */
#define F1_CONDITIONS    0x1499e09d8   /* variable id slot: a creature's conditions array (element 0 = count) */
#define F1_HP_VAR        0x1499e0a88
#define F1_CRITS_VAR     0x1499e0668   /* global.crits */
#define F1_ENEMIES_VAR   0x1499e06a8   /* global.enemies */

typedef RValue *(*F1ArrGet)(RValue *arr, int i);
typedef double (*F1IRandom)(long long lo, long long hi);

/* ---- SU-0045 Unrealized Potential: "they gain these stats an additional time, but they gain 50% fewer stats".
 * Each stat-gain builder halves the gain (L339 in Attack) and then queues the copy with that already halved amount;
 * the copy is halved again on its own pass (100 -> 50 + 25). User ruling: the total is split evenly over two
 * events (50 + 50). Stands in for the var get of `amount` that feeds the copy (one per builder): the copy is queued
 * with the pre-halving amount, so its own halving makes it 50. */
static void *hook_su0045_copy_amount(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    void *r = ((VarGet)RVA(F1_VARGET))(inst, var_id, index, out, a5, a6);
    int ok; double x = a2_num(out, &ok);
    if (ok) a2_set_real(out, x * 2.0);
    return r;
}

/* ---- SU-0052 Sugar Rush: "At the end of this creature's turn, its buffs are removed." The end-of-turn loop walks the
 * conditions array forwards (bc_CreatureEndOfTurn L239-L241) and each removal shifts the array, so the buff after a
 * removed one is skipped (in-game confirmed). Stands in for the loop's scr_CritRemoveCondition: if the array really
 * shrank, the loop's own "first pass" flag ([caller rsp + 0x309]) is set so the next pass re-checks the same index
 * instead of advancing. A buff that resists removal leaves the count unchanged, so the loop still advances. */
static RValue *hook_su0052_remove(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *caller = (char *)_AddressOfReturnAddress() + 8;
    RValue *who = *(RValue **)(caller + 0x48);              /* the creature the loop walks (bound read @0x140ac1acd) */
    RValue n0, n1, *r;
    int ok0 = 0, ok1 = 0; double c0 = 0, c1 = 0;
    memset(&n0, 0, sizeof n0); memset(&n1, 0, sizeof n1);
    if (who) { ((VarGet)RVA(F1_VARGET))(who, *(int *)RVA(F1_CONDITIONS), 0, &n0, 0, 0); c0 = a2_num(&n0, &ok0); }
    r = ((GmlScript)RVA(F1_REMOVE_COND))(self, other, ret, argc, args);
    if (who && ok0) {
        ((VarGet)RVA(F1_VARGET))(who, *(int *)RVA(F1_CONDITIONS), 0, &n1, 0, 0); c1 = a2_num(&n1, &ok1);
        if (ok1 && c1 < c0) *(BYTE *)(caller + 0x309) = 1;  /* skip the i++ once: re-check this index */
    }
    return r;
}

/* ---- SU-0064 Careful What You Wish For (1071) / Grim Ailment (1072): "... but their buffs / debuffs only last for 1
 * turn." The limit is not implemented anywhere. Called from hook_su0080_add_condition (the three buff/debuff event
 * sites), which already knows the event's source: buffs gained by a creature whose side holds 1071, and debuffs
 * applied by a creature whose side holds 1072, get duration 1. Permanent conditions (-2) are left alone. Returns the
 * argument array to pass on (a copy with the new duration, or the original). hook_su0080 reaches it through the SU-0064
 * patch slot (0x149ed86c0, filled by the loader), so with SU-0064 off the arguments pass unchanged. */
static RValue *f1_ring_args[16][8];
static RValue f1_ring_dur[16];
static unsigned f1_ring_i;
static int f1_is_creature(RValue *v)
{
    unsigned k = v->kind & 0xffffff;
    if (k == 0) return v->v.real > 0;                        /* instance id; events with no source carry -1 */
    return k == 6 || k == 15;
}
static RValue **f1_su0064_args(void *self, void *other, int argc, RValue **args, RValue *src)
{
    RValue id, *cond[1];
    int one = 0, k;
    unsigned slot;
    if (argc < 3 || argc > 8 || !args || !args[0] || !args[1] || !args[2]) return args;
    if (((CmpEqInt)RVA(0x14028c8f0))(args[2], -2)) return args;
    cond[0] = args[1];
    if (e_call(E_IS_BUFF, self, other, 1, cond)) {
        memset(&id, 0, sizeof id); id.v.real = 1071.0;
        one = e_side_has(e_is_enemy(args[0]), self, other, &id);
    } else if (src && f1_is_creature(src) && e_call(F1_IS_DEBUFF, self, other, 1, cond)) {
        memset(&id, 0, sizeof id); id.v.real = 1072.0;
        one = e_side_has(e_is_enemy(src), self, other, &id);
    }
    if (!one) return args;
    slot = f1_ring_i++ & 15;                                 /* ring: nested adds each get their own copy */
    for (k = 0; k < argc; k++) f1_ring_args[slot][k] = args[k];
    memset(&f1_ring_dur[slot], 0, sizeof f1_ring_dur[slot]);
    f1_ring_dur[slot].v.real = 1.0;
    f1_ring_args[slot][2] = &f1_ring_dur[slot];
    return f1_ring_args[slot];
}

/* ---- SU-0170 (Christmas Is Canceled half) Master of Stags: "their innate traits are 100% more effective"; user
 * ruling: Christmas Is Canceled ("At the start of battle, this creature afflicts 3 random enemies with Disarmed")
 * afflicts 6. The block (bc_StartupBuffsDebuffs L1414-L1469) picks 3 distinct random enemies into a local array
 * ([caller rsp + 0x290], element 0 = count) and adds Disarmed to each through one scr_CritAddCondition call. The gate
 * hook (its scr_CritHasPassive(creature, 1020)) remembers the holder; on the block's first add, when the holder's side
 * passes the game's own Master test (b2_stags), up to 3 more distinct living enemies get the same add. */
static RValue f1_xmas_holder;
static int f1_xmas_armed;
static RValue *hook_su0170_xmas_gate(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(E_HAS_PASSIVE))(self, other, ret, argc, args);
    f1_xmas_armed = 0;
    if (argc >= 1 && args && args[0] && e_truthy(r, ret)) { f1_xmas_holder = *args[0]; f1_xmas_armed = 1; }
    return r;
}

static int f1_list_get(unsigned long long list_var, int i, RValue *out)
{
    RValue g;
    memset(&g, 0, sizeof g); memset(out, 0, sizeof *out);
    ((A2WrapGlobal)RVA(0x140297c20))(&g, *(void **)RVA(0x1499f57c8));
    ((VarGet)RVA(F1_VARGET))(&g, *(int *)RVA(list_var), i, out, 0, 0);
    ((A2Free)RVA(0x14028c220))(&g);
    return ((CmpInt)RVA(0x14028ca10))(out, -1) != 0;        /* empty slots hold -1 */
}

static RValue *hook_su0170_xmas_add(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(F1_ADD_CONDITION))(self, other, ret, argc, args);
    char *caller = (char *)_AddressOfReturnAddress() + 8;
    RValue *picked = (RValue *)(caller + 0x290);
    RValue cand[6], chosen[8], *e;
    int enemy, nc = 0, nchosen = 0, i, j, k, ok, extra = 0;
    double n;
    if (!f1_xmas_armed || argc < 1 || argc > 8 || !args || !args[0]) return r;
    f1_xmas_armed = 0;                                       /* once per block */
    enemy = e_is_enemy(&f1_xmas_holder);
    if (!b2_stags(self, other, enemy)) return r;
    e = ((F1ArrGet)RVA(F1_ARR_GET))(picked, 0);              /* the block's own picks: exclude them */
    if (!e) return r;
    n = a2_num(e, &ok);
    for (i = 1; ok && i <= (int)n && nchosen < 8; i++) {
        e = ((F1ArrGet)RVA(F1_ARR_GET))(picked, i);
        if (e) chosen[nchosen++] = *e;
    }
    for (i = 1; i <= 6; i++) {                               /* the holder's enemies, alive, not already afflicted */
        RValue c, hp; int dup = 0;
        if (!f1_list_get(enemy ? F1_CRITS_VAR : F1_ENEMIES_VAR, i, &c)) continue;
        hp = e_var(&c, F1_HP_VAR);
        if (!((CmpInt)RVA(0x14028ca10))(&hp, 0)) continue;
        for (j = 0; j < nchosen; j++) if (((A2Eq)RVA(0x14028c8d0))(&c, &chosen[j])) dup = 1;
        if (!dup) cand[nc++] = c;
    }
    while (extra < 3 && nc > 0) {                            /* 3 more, random, distinct */
        RValue res, *a[8];
        k = (int)((F1IRandom)RVA(F1_IRANDOM))(0, nc - 1);
        if (k < 0 || k >= nc) break;
        for (j = 0; j < argc; j++) a[j] = args[j];
        a[0] = &cand[k];
        memset(&res, 0, sizeof res);
        ((GmlScript)RVA(F1_ADD_CONDITION))(self, other, &res, argc, a);
        cand[k] = cand[--nc];
        extra++;
    }
    return r;
}
