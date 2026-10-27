/* Hook batch A2 (round 2; see research/hook_batches.json). Included by hooks.c.
 * Built by research/build_hooks_A2.py. Game addresses are 2.0.38 VAs, rebased with RVA(). */

/* ---------- helpers ---------- */

/* RValue -> double for the numeric kinds the runtime uses (real 0, int32 7, int64 10, bool 13). ok = 0 otherwise. */
static double a2_num(const RValue *v, int *ok)
{
    unsigned k = v->kind & 0xffffff;
    *ok = 1;
    if (k == 0 || k == 13) return v->v.real;
    if (k == 7) return (double)(int)v->v.i64;
    if (k == 10) return (double)v->v.i64;
    *ok = 0;
    return 0;
}

static void a2_set_real(RValue *v, double x) { v->v.real = x; v->flags = 0; v->kind = 0; }

typedef void *(*A2WrapGlobal)(RValue *out, void *global_obj);     /* 0x140297c20: value wrapping the global object */
typedef void (*A2Free)(RValue *v);                                  /* 0x14028c220: release a temporary value */
typedef char (*A2Eq)(RValue *a, RValue *b);                         /* 0x14028c8d0: value == value */

/* crits[i] (your party, 1..6; empty slots hold -1), read exactly as the game does: wrap the global object, var get
 * with the index, release the wrapper. Returns 1 if the slot holds a creature. */
static int a2_crits_get(int i, RValue *out)
{
    RValue g;
    memset(&g, 0, sizeof g); memset(out, 0, sizeof *out);
    ((A2WrapGlobal)RVA(0x140297c20))(&g, *(void **)RVA(0x1499f57c8));
    ((VarGet)RVA(0x1478bbd70))(&g, *(int *)RVA(0x1499e0668), i, out, 0, 0);
    ((A2Free)RVA(0x14028c220))(&g);
    return ((CmpInt)RVA(0x14028ca10))(out, -1) != 0;
}

static int a2_var_num(RValue *inst, unsigned long long slot_va, double *x)
{
    RValue v; int ok;
    memset(&v, 0, sizeof v);
    ((VarGet)RVA(0x1478bbd70))(inst, *(int *)RVA(slot_va), (int)0x80000000, &v, 0, 0);
    *x = a2_num(&v, &ok);
    return ok;
}

/* Party snapshot: creature value + one number per creature, looked up with the runtime's == on values. */
typedef struct { int n; RValue who[6]; double val[6]; } A2Snap;

static void a2_snap_take(A2Snap *s, unsigned long long slot_va)
{
    int i; double x;
    s->n = 0;
    for (i = 1; i <= 6; i++) {
        RValue c;
        if (a2_crits_get(i, &c) && a2_var_num(&c, slot_va, &x)) { s->who[s->n] = c; s->val[s->n] = x; s->n++; }
    }
}

static int a2_snap_find(A2Snap *s, RValue *inst, double *x)
{
    int i;
    for (i = 0; i < s->n; i++)
        if (((A2Eq)RVA(0x14028c8d0))(inst, &s->who[i])) { *x = s->val[i]; return 1; }
    return 0;
}

typedef RValue *(*A2VarRef)(void *inst, int var_id);               /* 0x14028c090: pointer to an instance variable */

/* ---------- SU-0060 Windwalker ---------- */
/* "for each time all your creatures dodged": stands in for the var get of the damaged creature's total_dodges
 * (bc_EventDamage L181). For your creatures it returns the party's total; enemies keep their own count (the perk only
 * applies to your side, L183). */
static void *hook_su0060_varget(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    void *r = varget(inst, var_id, index, out, a5, a6);
    double slot, sum = 0, x;
    int i;
    if (var_id != *(int *)RVA(0x1499e2be8) || !a2_var_num(inst, 0x1499e0aa8, &slot) || !(slot > 0)) return r;
    for (i = 1; i <= 6; i++) {
        RValue c;
        if (a2_crits_get(i, &c) && a2_var_num(&c, 0x1499e2be8, &x)) sum += x;
    }
    a2_set_real(out, sum);
    return r;
}

/* ---------- SU-0133 Union ---------- */
/* "grant X% of their highest stat": the Health share reads each ally's CURRENT Max Health one creature after another,
 * so earlier gains feed later ones. Snapshot your creatures' Max Health around bc_StartupStatGain and answer the
 * Health share's read (L787) from the snapshot. */
static A2Snap a2_union_snap;
static int a2_union_on;
static RValue *hook_su0133_startup(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r;
    a2_snap_take(&a2_union_snap, 0x1499e0b68);              /* hpmax */
    a2_union_on = 1;
    r = ((GmlScript)RVA(0x141710e10))(self, other, ret, argc, args);
    a2_union_on = 0;
    return r;
}
static void *hook_su0133_varget(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    void *r = ((VarGet)RVA(0x1478bbd70))(inst, var_id, index, out, a5, a6);
    double x;
    if (a2_union_on && var_id == *(int *)RVA(0x1499e0b68) && a2_snap_find(&a2_union_snap, inst, &x)) a2_set_real(out, x);
    return r;
}

/* ---------- SU-0086 5740-NG rank 10 ---------- */
/* "if the bearer didn't take any damage": the game tests `damages == 0`, but `damages` counts every damage event aimed
 * at the creature since the turn began, including avoided, dodged and prevented hits. At the turn-start reset of
 * `damages` (bc_CreatureStartOfTurn L54) snapshot each party creature's damage_taken; the rank-10 check
 * (bc_CreatureEndOfTurn L210) then sees 0 unless damage_taken has grown since. */
static A2Snap a2_ng_snap;
static int a2_ng_valid;
static RValue *hook_su0086_turnstart(void *inst, int var_id)
{
    a2_snap_take(&a2_ng_snap, 0x1499e1fe8);                 /* damage_taken */
    a2_ng_valid = 1;
    return ((A2VarRef)RVA(0x14028c090))(inst, var_id);
}
static void *hook_su0086_varget(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    void *r = ((VarGet)RVA(0x1478bbd70))(inst, var_id, index, out, a5, a6);
    double then, now;
    if (a2_ng_valid && var_id == *(int *)RVA(0x14992f508) && a2_snap_find(&a2_ng_snap, inst, &then)
        && a2_var_num(inst, 0x1499e1fe8, &now))
        a2_set_real(out, now > then ? 1 : 0);
    return r;
}

/* ---------- SU-0128 Born Again ---------- */
/* "killed from start-of-battle effects": the battle controller sets global.bornagain = true straight after the last
 * start-of-battle effect, before their queued kills (Red Wedding) resolve. That write is removed; this hook sets it at
 * the first turn start instead (bc_CreatureStartOfTurn L53), after the start-of-battle queue has drained. */
typedef RValue *(*A2GlobalRef)(void *global_obj, int var_id);       /* 0x140297c10 */
typedef RValue *(*A2MakeBool)(RValue *out, char value);             /* 0x14028c3b0 */
typedef void (*A2Assign)(RValue *dst, RValue *src);                 /* 0x14028c410 */
static RValue *hook_su0128_turnstart(void *inst, int var_id)
{
    RValue tmp, *b, *ref;
    memset(&tmp, 0, sizeof tmp);
    ref = ((A2GlobalRef)RVA(0x140297c10))(*(void **)RVA(0x1499f57c8), *(int *)RVA(0x1499bdfb8));
    if (ref) {
        b = ((A2MakeBool)RVA(0x14028c3b0))(&tmp, 1);
        ((A2Assign)RVA(0x14028c410))(ref, b ? b : &tmp);
        ((A2Free)RVA(0x14028c220))(&tmp);
    }
    return ((A2VarRef)RVA(0x14028c090))(inst, var_id);
}

/* ---------- SU-0151 Filtered Truth ---------- */
/* "Enemies always have equal Attack and Intelligence; whichever is lower." The game caps each against the other's
 * stored base field before bonuses (removed). These wrap crit_attack / crit_intelligence at their entry: after the real
 * getter, if the creature is an enemy of a Filtered Truth holder, return the lower of its two FINAL values. The partner
 * is computed with the guard set, so the getters never recurse into each other. */
static int a2_ft_guard;
static int a2_ft_applies(void *self, void *other, RValue *c)
{
    double slot;
    if (!a2_var_num(c, 0x1499e0aa8, &slot)) return 0;
    if (slot == 0) return call_gate((GmlScript)RVA(0x141f0a8a0), self, other, 41.0);   /* scr_AnyAllyHasPassive */
    if (slot > 0) return call_gate((GmlScript)RVA(0x141f0b2d0), self, other, 41.0);    /* scr_AnyEnemyHasPassive */
    return 0;
}
static RValue *a2_ft_wrap(unsigned long long own_orig, unsigned long long partner_orig,
                          void *self, void *other, RValue *ret, int argc, RValue **args)
{
    RValue *r = ((GmlScript)RVA(own_orig))(self, other, ret, argc, args), part, *q;
    double a, b; int ok1, ok2;
    if (a2_ft_guard || argc < 1 || !args || !args[0] || !r) return r;
    a2_ft_guard = 1;
    if (a2_ft_applies(self, other, args[0])) {
        memset(&part, 0, sizeof part);
        q = ((GmlScript)RVA(partner_orig))(self, other, &part, argc, args);
        a = a2_num(r, &ok1); b = a2_num(q ? q : &part, &ok2);
        if (ok1 && ok2 && b < a) a2_set_real(r, b);
    }
    a2_ft_guard = 0;
    return r;
}
/* own entry trampolines (relocated prologue + jmp back), in the code cave: crit_attack 0x1488bf850,
 * crit_intelligence 0x1488bf860 */
static RValue *hook_su0151_attack(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return a2_ft_wrap(0x1488bf850, 0x1488bf860, self, other, ret, argc, args);
}
static RValue *hook_su0151_intelligence(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    return a2_ft_wrap(0x1488bf860, 0x1488bf850, self, other, ret, argc, args);
}
