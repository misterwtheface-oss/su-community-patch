/* Runtime hooks: C functions that game code reaches through a cave trampoline (jmp [slot]); the loader writes each
 * function's address into its slot after the patch's edits are applied. Game addresses are written as 2.0.38 VAs and
 * rebased with RVA() (the game uses ASLR). Every hook must keep the exact signature of the function it stands in for.
 * Included by suucp.c. */

/* GameMaker runtime value: 8-byte payload, flags, kind (0 = real). */
typedef struct { union { double real; long long i64; void *ptr; } v; unsigned flags; unsigned kind; } RValue;
/* Compiled GML script: (self, other, result, argc, args). */
typedef RValue *(*GmlScript)(void *self, void *other, RValue *ret, int argc, RValue **args);
/* YYC variable get: (instance value, variable id, array index or 0x80000000, out, 0, 0). */
typedef void *(*VarGet)(RValue *inst, int var_id, int index, RValue *out, int a5, int a6);

static BYTE *g_base;
#define RVA(va) (g_base + ((unsigned long long)(va) - 0x140000000ULL))

/* SU-0080 Primordial Curse / Forsaken Wonder. Stands in for scr_CritAddCondition at the three buff/debuff event
 * sites in bc_ExecuteEvents, whose current event value lives at [caller rsp + 0x98e8]. Passes the event's source to
 * scr_CritAddCondition's own permanence check (see tools/build_h01b.py for the in-function detours). */
static RValue *hook_su0080_add_condition(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x142015940);          /* scr_CritAddCondition */
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    RValue *inflicter = (RValue *)RVA(0x149ed81c0);
    BYTE *flag = RVA(0x149ed81d0);
    int source_var = *(int *)RVA(0x1499e0c38);              /* variable id of `source` */
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    RValue *event = (RValue *)(caller_rsp + 0x98e8);
    RValue saved = *inflicter, src;
    BYTE saved_flag = *flag;
    RValue *r;

    memset(&src, 0, sizeof src);
    varget(event, source_var, (int)0x80000000, &src, 0, 0);
    *inflicter = src;
    *flag = 1;
    r = orig(self, other, ret, argc, *(void **)RVA(0x149ed86c0)   /* SU-0064 slot: f1_su0064_args (hooks_F1.c) */
             ? ((RValue **(*)(void *, void *, int, RValue **, RValue *))*(void **)RVA(0x149ed86c0))(self, other, argc, args, &src)
             : args);
    *flag = saved_flag;                                     /* nesting-safe */
    *inflicter = saved;
    return r;
}

typedef char (*ToBool)(RValue *v);                       /* the runtime's RValue -> bool used after every gate */
typedef char (*CmpInt)(RValue *v, int n);                 /* the runtime's "value > int" compare (any numeric kind) */

/* Call a one-argument GML script with a real argument; returns its result as a bool. */
static int call_gate(GmlScript fn, void *self, void *other, double arg)
{
    ToBool to_bool = (ToBool)RVA(0x147871cf0);
    RValue a, res, *pa = &a, *r;
    memset(&a, 0, sizeof a); memset(&res, 0, sizeof res);
    a.v.real = arg;                                      /* kind 0 = real */
    r = fn(self, other, &res, 1, &pa);
    return to_bool(r ? r : &res) != 0;
}

/* SU-0002 Master of Gorgons. Stands in for bc_CountRace at its one call in the Gorgon bonus block of bc_EventDamage
 * (amount += amount x 0.35 x Gorgons on the attacker's side; the game never tests trait 1442). If the attacker's side
 * doesn't hold Master of Gorgons, report 0 Gorgons, so the bonus is 0. Same two-sided form the game uses for the other
 * Master traits: your attacker (slot > 0) -> scr_AnyAllyHasPassive, enemy attacker (slot 0) -> scr_AnyEnemyHasPassive.
 * bc_EventDamage's self value lives at [caller rsp + 0x21ef8]; the block already requires source != -1. */
static RValue *hook_su0002_count_race(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x14068f7b0);           /* bc_CountRace */
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    char *caller_rsp = (char *)_AddressOfReturnAddress() + 8;
    RValue *self_value = (RValue *)(caller_rsp + 0x21ef8);
    RValue src, slot;
    int has;

    memset(&src, 0, sizeof src); memset(&slot, 0, sizeof slot);
    varget(self_value, *(int *)RVA(0x1499e0c38), (int)0x80000000, &src, 0, 0);   /* source */
    varget(&src, *(int *)RVA(0x1499e0aa8), (int)0x80000000, &slot, 0, 0);       /* source.slot */
    has = call_gate((GmlScript)RVA(((CmpInt)RVA(0x14028ca10))(&slot, 0) ? 0x141f0a8a0 : 0x141f0b2d0),
                    self, other, 1442.0);
    if (!has) {
        ret->v.real = 0; ret->flags = 0; ret->kind = 0;
        return ret;
    }
    return orig(self, other, ret, argc, args);
}

/* SU-0083 Brambleskin rank 20: "This relic and its bearer deal additional damage ... equal to 10% of the damage the
 * bearer has taken". The byte fix makes the bonus read source.damage_taken; this hook stands in for that one variable
 * read (bc_EventDamage L3157) so that when the attacker is the Relic object (critconstant == 967) it reads the
 * bearer's total (relic.owner.damage_taken) instead: events aimed at the relic are dropped, so its own total is 0. */
typedef char (*CmpEqInt)(RValue *v, int n);
static void *hook_su0083_varget(RValue *inst, int var_id, int index, RValue *out, int a5, int a6)
{
    VarGet varget = (VarGet)RVA(0x1478bbd70);
    CmpEqInt eq_int = (CmpEqInt)RVA(0x14028c8f0);
    RValue crit, owner;
    memset(&crit, 0, sizeof crit); memset(&owner, 0, sizeof owner);
    varget(inst, *(int *)RVA(0x1499e0738), (int)0x80000000, &crit, 0, 0);          /* critconstant */
    if (eq_int(&crit, 967)) {
        varget(inst, *(int *)RVA(0x1499e2b18), (int)0x80000000, &owner, 0, 0);     /* owner = the bearer */
        return varget(&owner, var_id, index, out, a5, a6);
    }
    return varget(inst, var_id, index, out, a5, a6);
}

/* Hook batches (filled by the batch work; see research/hook_batches.json) */
#include "hooks_R.c"
#include "hooks_E.c"
#include "hooks_S.c"
#include "hooks_C.c"
#include "hooks_A2.c"
#include "hooks_B2.c"
#include "hooks_C2.c"
#include "hooks_C3.c"
#include "hooks_F2.c"
#include "hooks_F1.c"
#include "hooks_G4.c"
#include "hooks_H.c"
#include "hooks_I.c"
#include "hooks_J.c"
#include "hooks_K.c"
#include "hooks_L.c"
#include "hooks_M.c"
