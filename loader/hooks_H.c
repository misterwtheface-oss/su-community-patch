/* Hook batch H (heavy; see research/build_hooks_H.py). Included by hooks.c. Both patches are group "heavy".
 * Game addresses are 2.0.38 VAs, rebased with RVA(). Our state lives in the data range 0x149ed86f0-0x149ed87ff.
 *
 * SU-0055 (redirected attacks) is cave code only, no C: bc_CreatureAttack builds the target's Defense snapshot
 * (L182-L476) before the intercepts (Provoke, CAWW!, Barbed Vines, Vigilance, Pearl Keeper, Pocket Tank, Pedigree
 * Safeguard, Guardian; L478-L690) pick the creature that is really hit. Detours at L182 / L407 / L478 / L696 remember
 * the first target and, when an intercept changed it, run L182-L476 once more for the new target (skipping the
 * already-resolved re-targets L407-L447 and the intercepts), then continue at L696. Keyed by the frame's rsp.
 *
 * SU-0136 (Fleshripper rank 50) is below: the rank-50 hit becomes one real Bleed tick of bc_CreatureStartOfTurn. */

#define H_SLOT_DMG   0x149ed8708
#define H_SLOT_ADD   0x149ed8710
#define H_SKIP       0x149ed8718    /* int: the tick replaced the hit, so the following event push is skipped */
#define H_DEPTH      0x149ed871c    /* int: nested bleed-only calls (a tick can Attack, which can proc rank 50 again) */
#define H_MAGIC_ARGC 0x53550136     /* argc that makes bc_CreatureStartOfTurn run only its Bleed block (cave stubs) */
#define H_MAX_DEPTH  3

typedef RValue *(*HGlobalRef)(void *global_obj, int var_id);        /* 0x140297c10: the global variable's value */

/* Kinds that are plain values (no reference count), safe to copy byte-wise: real, struct/instance, int32, int64, ref. */
static int h_plain(const RValue *v)
{
    unsigned k = v->kind & 0xffffff;
    return k == 0 || k == 6 || k == 7 || k == 10 || k == 15;
}

/* ===== SU-0136 Fleshripper rank 50: "After this relic or its bearer Attacks an enemy with Bleed, it has a 25% chance
 * to take damage from this debuff immediately." The game dealt a plain hit of bc_CalculateBleedDamage (bc_OnAttack
 * L1427), so nothing that reacts to Bleed damage fired (Fleshripper ranks 30 / 40 / 80 / 90, Hemophilia, Cauterize the
 * Wound, Bloodletting, Gutwretch, Brain Drain, Bloody Massacre, Cornered, Kiichi's Aggression / Onslaught, Bleed Out).
 * Stands in for that bc_EventDamage call: runs the start-of-turn Bleed block (tick count L1059-L1077 and the tick loop
 * L1096-L1243) for the target, by calling bc_CreatureStartOfTurn with argc = H_MAGIC_ARGC (the cave stubs jump from
 * L2 to L1059, from L1083 to L1096 and from L1252 to the epilogue) while global.creatureturn names the target, as it
 * does during that creature's own tick. The tick queues its own damage event, so the original push is skipped. */
static RValue *hook_h_su0136_damage(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    GmlScript orig = (GmlScript)RVA(0x140cda820);                   /* bc_EventDamage(-1, target, amount, ...) */
    int *skip = (int *)RVA(H_SKIP), *depth = (int *)RVA(H_DEPTH);
    RValue *turn, saved, tmp;

    if (argc < 2 || !args || !args[1] || !h_plain(args[1]) || *depth >= H_MAX_DEPTH)
        return orig(self, other, ret, argc, args);
    turn = ((HGlobalRef)RVA(0x140297c10))(*(void **)RVA(0x1499f57c8), *(int *)RVA(0x1499e1f18));   /* creatureturn */
    if (!turn || !h_plain(turn))
        return orig(self, other, ret, argc, args);
    saved = *turn;
    *turn = *args[1];
    memset(&tmp, 0, sizeof tmp); tmp.kind = 5;                       /* undefined */
    ++*depth;
    ((GmlScript)RVA(0x140b204e0))(self, other, &tmp, H_MAGIC_ARGC, args);   /* bc_CreatureStartOfTurn, Bleed only */
    --*depth;
    *turn = saved;                                                   /* nesting-safe: each level restores its own */
    ret->v.real = 0; ret->flags = 0; ret->kind = 0;
    *skip = 1;
    return ret;
}

/* The scr_AddEventToStack call right after (same line): skipped once when the tick replaced the hit. */
static RValue *hook_h_su0136_addevent(void *self, void *other, RValue *ret, int argc, RValue **args)
{
    int *skip = (int *)RVA(H_SKIP);
    if (*skip) {
        *skip = 0;
        ret->v.real = 0; ret->flags = 0; ret->kind = 0;
        return ret;
    }
    return ((GmlScript)RVA(0x141ef3830))(self, other, ret, argc, args);
}
