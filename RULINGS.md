# Rulings (user decisions; they govern every triage call)

| Date | Ruling |
|---|---|
| 2026-10-26 | **Numbers:** when the code and the text give different numbers, change the code to match the text. |
| 2026-10-26 *(superseded same day)* | ~~**Stat / scope / trigger wording:** when the code is coherent but the text names a different stat, scope or trigger (Blindside / Pustule scaling stat, Corpse Explosion scaling, Bolster "all damage", Beelzebub / Leviathan "any kill", Spiderlings, The Walking Dead's Health exclusion), the **text** is corrected to match the code.~~ Superseded by the text-is-the-contract ruling below. |
| 2026-10-26 | **The localization text is the contract** (supersedes the stat/scope ruling): every effect should operate as its in-game text describes, since that is what players expect without a patch. Code is changed to match the text wherever the text makes a claim, even where that makes the effect stronger than the bugged version. Text is corrected only where the game's own texts contradict each other (fix the one the code doesn't follow) or a text row is missing. Where the text is silent, nothing changes (app note only). |
| 2026-10-26 | **Text corrections:** short, in-line edits written as though they were always the game's text (the game's own style and `{TOKEN}` tags). Shipped through the game's `localization_override` folder; English only, other languages copied unchanged. Scope (after the text-is-the-contract ruling): contradictions between game texts and missing rows. |
| 2026-10-26 *(superseded same day)* | ~~**Multi-hit bonus pile-up (SU-0038):** not fixed.~~ Superseded: normalised so bonuses don't ramp across hits (SU-0038 patched). |
| 2026-10-26 | **In-game tests:** collected in one sheet (`IN_GAME_TESTS.md`, generated from the registry). |
| 2026-10-26 | **App:** the build calculator describes the base game only; at most a link to the public patch later. |
| 2026-10-26 | **Party-wide spells (SU-0191):** the hidden ×0.25 stays; one Codex line states it (no code change). |
| 2026-10-26 | **Start-of-battle grants (SU-0216, SU-0218):** buffs and minions granted at the start of battle trigger the same "after it gains" reactions as in-battle grants. Which start-of-battle *stat* effects count as gained stats is still open (Photosynthesis, Misery). |
| 2026-10-26 | **Jealousy (SU-0281) and Devotion (SU-0261):** use the shared race count, so Odd One, Shackler's Mastery and Forest Pact apply as their texts say. |
| 2026-10-26 | **Mesmer (SU-0290):** the code follows the literal text (the enemy becomes this creature's class weakness). |
| 2026-10-26 | **Lifelong Respite** (Nether Stone roll rounding, SU-0186): left as it is. |
| 2026-10-26 | **Fixed-amount spells and Enchanter properties** (SU-0232, 0236, 0238, 0251, 0252): pending a decision (make the properties work, stop offering them, or leave). |
