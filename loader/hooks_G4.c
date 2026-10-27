/* Hook batch G4 (round 4; see research/hook_batches.json / research/build_hooks_G4.py). Included by hooks.c.
 * Game addresses are 2.0.38 VAs, rebased with RVA(). Uses helpers from hooks.c and hooks_A2.c.
 * Our state lives in the data range 0x149ed85a0-0x149ed85ff (pointer slots, one saved rbp, the Witchcraft flag). */

#define G4_SAVED_RBP   0x149ed85e8      /* written by the heal / stat trampolines just before jumping here */
#define G4_WITCH_FLAG  0x149ed85f0
#define G4_SLOT_HP     0x1499e0a88
#define G4_SLOT_SLOT   0x1499e0aa8
#define G4_SLOT_ISRELIC 0x1499e2b78
#define G4_SLOT_ENEMIES 0x1499e06a8

typedef RValue *(*G4GlobalRef)(void *global_obj, int var_id);       /* 0x140297c10: the global variable's value */
typedef RValue *(*G4ElemRef)(RValue *arr, int index);                /* 0x14028c8a0: array element, for writing */
typedef void (*G4IntSet)(RValue *dst, int value);                    /* 0x14028c530: dst = int */
typedef void (*G4Assign)(RValue *dst, RValue *src);                  /* 0x14028c410: dst = src (refcounted copy) */
typedef double (*G4IRandom)(long long lo, long long hi);             /* 0x1478b83e0: irandom_range */

static RValue *g4_script(unsigned long long va, void *self, void *other, RValue *ret, int n, RValue **a)
{
    return ((GmlScript)RVA(va))(self, other, ret, n, a);
}

static RValue g4_real(double x) { RValue v; memset(&v, 0, sizeof v); v.v.real = x; return v; }

/* ===== SU-0109 Petra & Aes rank 70: "The potency of the bearer's spells is increased by 15% of its Speed." =====
 * The game added a flat 15% of Speed to the FINAL amount (after Defense and every modifier) in all three spell
 * calculators. Now 15% of Speed joins the casting-stat bonus pool, exactly where Swiftcasting's 35% of Speed goes
 * (bc_SpellDamage L417 -> pool [rsp+0xb768]; healing L117 / stat L116 -> pool [rbp+0xc0]); the pool is folded into
 * the casting stat by the scr_Diminish(stat, pool) call that follows (damage L437, healing L193, stat L232), which
 * is what we stand in for. The old flat add is skipped (byte edits). Same gate as the game's: scr_CritHasRelicPerk
 * (caster, 8 = Petra & Aes, 7 = rank 70); the Speed is crit_speed(caster), the value the flat add used. */
static int g4_petra70(void *self, void *other, RValue *caster)
{
    RValue r8 = g4_real(8), r7 = g4_real(7), res, *a[3], *r;
    memset(&res, 0, sizeof res);
    a[0] = caster; a[1] = &r8; a[2] = &r7;
    r = g4_script(0x14202d600, self, other, &res, 3, a);                     /* scr_CritHasRelicPerk */
    return ((ToBool)RVA(0x147871cf0))(r ? r : &res) != 0;
}

static RValue *g4_petra_diminish(RValue *caster, void *self, void *other, RValue *ret, int argc, RValue **args)
{
    if (caster && argc >= 2 && args && args[0] && args[1] && g4_petra70(self, other, caster)) {
        RValue sp, *a1[1], *s, pool2, *a2[2];
        double speed, pool;
        int ok1 = 0, ok2 = 0;
        memset(&sp, 0, sizeof sp);
        a1[0] = caster;
        s = g4_script(0x1417e3430, self, other, &sp, 1, a1);                 /* crit_speed(caster) */
        speed = a2_num(s ? s : &sp, &ok1);
        pool = a2_num(args[1], &ok2);
        if (ok1 && ok2) {
            pool2 = g4_real(pool + speed * 0.15);
            a2[0] = args[0]; a2[1] = &pool2;
            return g4_script(0x1460713c0, self, other, ret, 2, a2);          /* scr_Diminish(stat, pool + 15% Speed) */
        }
    }
    return g4_script(0x1460713c0, self, other, ret, argc, args);
}

/* bc_SpellDamage L437: caster = argument copy [caller rsp + 0xb728]. */
static RValue *hook_su0109_damage(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    return g4_petra_diminish((RValue *)(caller_rsp + 0xb728), self, other, ret, argc, args);
}
/* bc_SpellHealing L193: caster = argument copy [rbp - 0x50]; the trampoline saved the caller's rbp. */
static RValue *hook_su0109_healing(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *rbp = *(char **)RVA(G4_SAVED_RBP);
    return g4_petra_diminish(rbp ? (RValue *)(rbp - 0x50) : NULL, self, other, ret, argc, args);
}
/* bc_SpellStat L232: caster = argument copy [rbp - 0x40]. */
static RValue *hook_su0109_stat(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    char *rbp = *(char **)RVA(G4_SAVED_RBP);
    return g4_petra_diminish(rbp ? (RValue *)(rbp - 0x40) : NULL, self, other, ret, argc, args);
}

/* ===== SU-0135 Reliquary Stat Bonus: "Increases your relics' stats by 1% per rank." (Abandoned Altar: "Your
 * creatures' Relics gain 100% more benefit from Reliquary Upgrades.") =====
 * Each stat getter (crit_attack / crit_defense / crit_intelligence / crit_speed) starts with
 *   if (self.owner > -1) return crit_X(self.owner);        // L13-L17: a Relic mirrors its bearer
 * so the game's own Stat Bonus block further down (isrelic > -1: stat += stat x 0.01 x global rank, doubled by
 * scr_PerkLevel(656, side)) never runs for a Relic. We stand in for that redirect call and apply the same formula to
 * the mirrored stat: x (1 + 0.01 x rank x (Altar ? 2 : 1)), only when self is a Relic (isrelic > -1). The getter's
 * own creature value (self) is its argument copy at [caller rsp + 0x68]; rank is the global at slot 0x1499c0888. */
static RValue *g4_relic_stat(unsigned long long orig_va, char *caller_rsp, void *self, void *other, RValue *ret,
                             int argc, RValue **args)
{
    RValue *r = g4_script(orig_va, self, other, ret, argc, args);
    RValue *relic = (RValue *)(caller_rsp + 0x68), isr, slot, *gr, side, p656, *a[2], res, *pr;
    double rank, v, mult = 1;
    int ok1, ok2;
    memset(&isr, 0, sizeof isr); memset(&slot, 0, sizeof slot); memset(&res, 0, sizeof res);
    ((VarGet)RVA(0x1478bbd70))(relic, *(int *)RVA(G4_SLOT_ISRELIC), (int)0x80000000, &isr, 0, 0);
    if (!((CmpInt)RVA(0x14028ca10))(&isr, -1)) return r;                      /* not a Relic: unchanged */
    gr = ((G4GlobalRef)RVA(0x140297c10))(*(void **)RVA(0x1499f57c8), *(int *)RVA(0x1499c0888));
    rank = gr ? a2_num(gr, &ok1) : (ok1 = 0, 0);
    if (!ok1 || !(rank > 0) || !r) return r;
    ((VarGet)RVA(0x1478bbd70))(relic, *(int *)RVA(G4_SLOT_SLOT), (int)0x80000000, &slot, 0, 0);
    side = g4_real(((CmpEqInt)RVA(0x14028c8f0))(&slot, 0) ? 0 : 1);          /* L395: slot 0 -> side 0, else 1 */
    p656 = g4_real(656);
    a[0] = &p656; a[1] = &side;
    pr = g4_script(0x1464eb110, self, other, &res, 2, a);                   /* scr_PerkLevel(656, side) */
    if (((ToBool)RVA(0x147871cf0))(pr ? pr : &res)) mult = 2;
    v = a2_num(r, &ok2);
    if (ok2) a2_set_real(r, v * (1 + 0.01 * rank * mult));
    return r;
}
static RValue *hook_su0135_attack(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return g4_relic_stat(0x1417aa4d0, (char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args); }
static RValue *hook_su0135_defense(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return g4_relic_stat(0x1417bc7d0, (char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args); }
static RValue *hook_su0135_intelligence(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return g4_relic_stat(0x1417cf710, (char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args); }
static RValue *hook_su0135_speed(void *self, void *other, RValue *ret, int argc, RValue **args)
{ return g4_relic_stat(0x1417e3430, (char *)_AddressOfReturnAddress() + 8, self, other, ret, argc, args); }

/* ===== SU-0143 Witchcraft: "Enemies with Cursed cast one of their single-target damage spells on a random
 * creature." =====
 * The Cursed auto-cast (bc_CreatureCast L1880) calls bc_CreatureCastSpellGem(caster, gem, auto) with no target; for
 * a damage gem no tag branch picks one, so its targets array ([rbp+0xb8]: [0] = count, [1..] = creatures) is filled
 * with the caster's opponents (L135-L140), i.e. always your creatures. We flag that one call, and at the cast's
 * bc_EventCast(caster, targets, gem, auto) (L288) rewrite the targets array to exactly one random living creature
 * from either side (the caster excluded). Random pick uses the game's irandom_range. Fail safe: no living creature
 * found, or anything unexpected, leaves the game's own targets. */
static RValue *hook_su0143_cast(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    int *flag = (int *)RVA(G4_WITCH_FLAG), saved = *flag;
    RValue *r;
    *flag = 1;
    r = g4_script(0x140aab480, self, other, ret, argc, args);                /* bc_CreatureCastSpellGem */
    *flag = saved;
    return r;
}

static int g4_enemies_get(int i, RValue *out)
{
    RValue g;
    memset(&g, 0, sizeof g); memset(out, 0, sizeof *out);
    ((A2WrapGlobal)RVA(0x140297c20))(&g, *(void **)RVA(0x1499f57c8));
    ((VarGet)RVA(0x1478bbd70))(&g, *(int *)RVA(G4_SLOT_ENEMIES), i, out, 0, 0);
    ((A2Free)RVA(0x14028c220))(&g);
    return ((CmpInt)RVA(0x14028ca10))(out, -1) != 0;
}

static RValue *hook_su0143_eventcast(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    int *flag = (int *)RVA(G4_WITCH_FLAG);
    if (*flag && argc >= 2 && args && args[0] && args[1]) {
        RValue pool[12], c, hp;
        int n = 0, i, side;
        *flag = 0;                                                           /* this cast only */
        for (side = 0; side < 2; side++)
            for (i = 1; i <= 6; i++) {
                if (!(side ? g4_enemies_get(i, &c) : a2_crits_get(i, &c))) continue;
                if (((A2Eq)RVA(0x14028c8d0))(&c, args[0])) continue;         /* not the caster itself */
                memset(&hp, 0, sizeof hp);
                ((VarGet)RVA(0x1478bbd70))(&c, *(int *)RVA(G4_SLOT_HP), (int)0x80000000, &hp, 0, 0);
                if (!((CmpInt)RVA(0x14028ca10))(&hp, 0)) continue;           /* living only */
                pool[n++] = c;
            }
        if (n > 0) {
            int pick = (int)((G4IRandom)RVA(0x1478b83e0))(0, n - 1);
            if (pick < 0 || pick >= n) pick = 0;
            ((G4IntSet)RVA(0x14028c530))(((G4ElemRef)RVA(0x14028c8a0))(args[1], 0), 1);
            ((G4Assign)RVA(0x14028c410))(((G4ElemRef)RVA(0x14028c8a0))(args[1], 1), &pool[pick]);
        }
    }
    return g4_script(0x140cd8d00, self, other, ret, argc, args);              /* bc_EventCast */
}
