/* Hook batch C3 (round 3; see research/hook_batches.json): splash damage in the form of the Splashing buff.
 * Included by hooks.c. Uses a2_var_num from hooks_A2.c.
 *
 * Splashing (bc_OnAttack L37-L99) is the reference: a new bc_EventDamage per adjacent enemy for 50% of the damage the
 * attack actually dealt, dtype -1 (indirect, so the attack's / spell's own bonuses and crit roll don't apply again), with
 * its own label (so it can't re-trigger label-keyed effects), keeping the attacker as source (kill credit and on-kill
 * effects work normally).
 *
 * SU-0140 Internal Combustion is a pure byte edit (see research/build_hooks_C3.py): its on-kill splash already uses
 * 25% of the damage dealt to the killed target, keeps the hit's source and has no label (so it can't chain into another
 * explosion); only its dtype (1 = spell, re-running the spell bonuses and crit) changes to -1, Splashing's form. */

/* SU-0164 Kiichi's Aggression: "After an enemy takes damage from Bleeding, all other enemies take 50% of that damage."
 * The game computes the splash from the Bleed formula before the tick goes through the damage builder. The builder
 * fixes an event's final amount when it is built, so: hook the tick's bc_EventDamage call (bc_CreatureStartOfTurn,
 * built before the Kiichi block in the same start of turn) and remember the amount it will deal; then the Kiichi
 * splash calls use 50% of that. A prevented tick (builder returns -1) means no damage was taken: no splash. */
static double c3_tick_amount;
static int c3_tick_state;                                   /* 0 = none seen, 1 = amount known, 2 = tick prevented */

static RValue *hook_su0164_bleed_tick(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x140cda820);           /* bc_EventDamage */
    RValue *r = orig(self, other, ret, argc, args);
    RValue *ev = r ? r : ret;
    double x = 0;
    if ((ev->kind & 0xffffff) == 0 && ev->v.real < 0) {      /* -1: the builder dropped the hit */
        c3_tick_state = 2;
    } else if (a2_var_num(ev, 0x1499c91b8, &x)) {           /* event.amount */
        c3_tick_amount = x; c3_tick_state = 1;
    } else {
        c3_tick_state = 0;                                  /* unknown shape: leave the game's own splash amount */
    }
    return r;
}

static RValue *hook_su0164_kiichi(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x140cda820);
    if (c3_tick_state == 2) {                               /* the Bleed tick dealt nothing: no splash */
        ret->v.real = -1; ret->flags = 0; ret->kind = 0;
        return ret;
    }
    if (c3_tick_state == 1 && argc >= 3 && argc <= 16 && args && args[2]) {
        RValue *a[16], amt;
        int i;
        for (i = 0; i < argc; i++) a[i] = args[i];
        memset(&amt, 0, sizeof amt);
        amt.v.real = c3_tick_amount * 0.5;                   /* 50% of the damage the tick deals */
        a[2] = &amt;
        return orig(self, other, ret, argc, a);
    }
    return orig(self, other, ret, argc, args);              /* fail safe: the game's own amount */
}
