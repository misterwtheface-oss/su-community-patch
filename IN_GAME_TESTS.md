# In-game tests (generated from bugs/ by tools/registry.py; do not edit)

Record results in the bug's `builds["2.0.38"].verified_in_game` (or tell the patch session).
Switch any fix off in `suucp.ini` ([fixes] SU-xxxx=0; text: [text] SU-xxxx=0).

## 1. Confirm the live fixes

### Relics

- [ ] **SU-0006** Lamora rank 90. Expect: Lamora rank 90: +30% Intelligence per enemy with Blighted only from rank 90 (code applied it from rank 30)
- [ ] **SU-0007** Brambleskin rank 100. Expect: Brambleskin rank 100: the first time the bearer is killed, it resurrects with 100% Health and gains 50% stats (its rank test never passed on a real death)
- [ ] **SU-0008** Fable rank 80 (on-death half). Expect: Fable rank 80: the bearer's on-death effects activate 1 additional time (its rank test never passed on a real death)
- [ ] **SU-0009** Starwrath rank 100. Expect: Starwrath rank 100: enemies without Confused get a 10% chance to act as if Confused; Confused enemies keep their normal chance (code lowered them to 10%)
- [ ] **SU-0030** Fable rank 50. Expect: Fable rank 50: the bearer's on-debuff effects activate 1 additional time, as on-buff ones already do (code: only Unbound Hatred repeated them)
- [ ] **SU-0086** 5740-NG rank 10. Expect: 5740-NG rank 10: the relic attacks only if the bearer really took no damage this turn (avoided, dodged and prevented hits no longer count)
- [ ] **SU-0087** Amalgam ranks 50 / 60 / 100. Expect: Amalgam ranks 50 / 60 / 100: work only on an enemy's Inverted, as the texts say (code: your own Inverted creatures healed enemies twice, kept and regained their Inverted)
- [ ] **SU-0109** Petra & Aes. Expect: Petra & Aes (rank 70): spell potency increased by 15% of Speed, folded into the casting stat like Swiftcasting (code: flat 15% of Speed added to the final amount)
- [ ] **SU-0136** Fleshripper rank 50. Expect: Fleshripper rank 50: the extra damage is a real Bleed tick, so every Bleed-damage modifier and reaction applies (code: a plain hit of the Bleed amount)
- [ ] **SU-0225** Materium, Shifting Gem of Aurum rank 30. Expect: Materium, Shifting Gem of Aurum rank 30: hits from a class strong against the bearer also end as if the bearer were strong (code: they still dealt double damage)
- [x] **SU-0003** Triumvir rank 80. Expect: Triumvir rank 80: 50% chance to give Arcane after a manual cast (code required Arcane already) *(last result: works as intended: gives Arcane with no Arcane present at the time of the cast (bug itself not observed before the patch))*
- [x] **SU-0004** Arbiter rank 60. Expect: Arbiter rank 60: the bearer gives 100% more healing (code boosted healing it received) *(last result: works: healing given by the Arbiter bearer is increased (bug itself not observed before the patch))*
- [x] **SU-0005** Lamora rank 70. Expect: Lamora rank 70: 50% more healing to Blighted enemies from the relic and its bearer (code tested the healed enemy) *(last result: works: the bearer's healing on enemy-side (Blighted) targets is increased)*
- [x] **SU-0012** Materium rank 100. Expect: Materium rank 100: no second copy of the rank-90 cast roll (rank 100 should only allow Sorcery gems) *(last result: user ruling: hard to verify in game (needs many casts); code validation suffices)*
- [x] **SU-0083** Brambleskin rank 20. Expect: Brambleskin rank 20: the relic and its bearer deal additional damage equal to 10% of the damage the bearer has taken (code: 10% x the hit x turns taken) *(last result: user ruling: code validation suffices)*

### Traits

- [ ] **SU-0001** Sleight of Hand, Spin the Wheel, Good Luck (Enemies). Expect: Sleight of Hand / Spin the Wheel / Good Luck (Enemies) re-roll during battle
- [ ] **SU-0002** Master of Gorgons. Expect: Master of Gorgons: the Gorgon damage bonus needs the trait on the attacker's side (code gave it to every Gorgon). Confirmed in game
- [ ] **SU-0013** Shifting Brilliance, Enochian, Add to the Mix. Expect: Shifting Brilliance / Enochian / Add to the Mix: compare with the spell cast just before (code: the current spell or the battle's first). Needs SU-0123 (shared on-cast hook)
- [ ] **SU-0014** Master of Dragons + Dynamic Dragon Scales. Expect: Master of Dragons: your Dragons' Dynamic Dragon Scales activates 1 additional time (code tested the enemy caster's race and side, so your Dragons never got it)
- [ ] **SU-0016** Celestial Nexus. Expect: Celestial Nexus: takes hits for your other creatures while IT has Barrier or Shell (code tested the creature that was hit)
- [ ] **SU-0017** Incoming Tide. Expect: Incoming Tide: 50% chance to cast Submerge at the start of the holder's turn (code: empty statement, never cast)
- [ ] **SU-0018** Eternal Rest. Expect: Eternal Rest: 10% Sleeping roll only at the end of each enemy turn (code also rolled at the start)
- [ ] **SU-0019** SKREEE!!. Expect: SKREEE!!: 20% Confused roll only at the start of each enemy turn (code also rolled at the end)
- [ ] **SU-0020** Christmas Music Sucks. Expect: Christmas Music Sucks: only non-damaging spells use Barrier absorption as potency (code also changed damaging spells)
- [ ] **SU-0021** Creationism. Expect: Creationism: only damaging Nature spells get the Intelligence contributions (code: every damaging spell)
- [ ] **SU-0022** Piercing Dragon Claws (minion half). Expect: Piercing Dragon Claws: 30% of Speed after an enemy gains a minion (code had 25%; the buff half already used 30%)
- [ ] **SU-0023** Book of the Arsonist. Expect: Book of the Arsonist: enemies' Burned debuffs it applies deal 30% more damage (code boosted every debuff it applied)
- [ ] **SU-0026** Giran (Nether boss). Expect: Giran's Lifeblood: each stat gains a share of the other creatures' same stat (code used their Attack for every stat)
- [ ] **SU-0028** Master of Cataclysms. Expect: Master of Cataclysms: only your all-Cataclysm party's traits get the 10% activation (code: enemies' Wrath traits rolled too). Partial: the 'each creature's turn' half is not built
- [ ] **SU-0029** Ejector Seat. Expect: Ejector Seat: ignored if an ally has the same trait, for indirect damage too (code: only the attack/spell immunity checked allies)
- [ ] **SU-0031** Single Discipline. Expect: Single Discipline: +10% Intelligence per time the spell was cast at once (code: +10% x count on every execution, i.e. count squared)
- [ ] **SU-0032** Master of Spelljugglers. Expect: Shifting Brilliance / Enochian / Add to the Mix: compare with the spell cast just before (code: the current spell or the battle's first). Needs SU-0123 (shared on-cast hook)
- [ ] **SU-0034** Bouquet (boss tier 930). Expect: Bouquet (tier 930): Barrier granted once at the end of its turn (code also ran a second, copied list block)
- [ ] **SU-0037** Tumble. Expect: Tumble: the +50% potency goes to the holder's own side's Cascading gems (code gave it to the opposing side; the 3-charge cost was already right)
- [ ] **SU-0039** Roulette. Expect: Roulette: otherwise the hit deals 50% more damage (code halved it)
- [ ] **SU-0040** Mindbender. Expect: Mindbender: an avoided spell deals no damage at all (its bonus damage no longer lands)
- [ ] **SU-0041** Focused Magicks. Expect: Focused Magicks: Ethereal gems ignore 30% of Defense plus 10% per missing creature (code: 30% x 10% x missing, 0 with a full party)
- [ ] **SU-0042** Reliquary heal upgrade (+ Abandoned Altar). Expect: Reliquary heal upgrade: heals from your Relics are increased by the Reliquary heal upgrade, doubled with Abandoned Altar (code computed the bonus and never applied it)
- [ ] **SU-0043** Cloak of Shadows, Immobility, Enchanted Arrows. Expect: Cloak of Shadows, Immobility, Enchanted Arrows: activate once per turn (code: once per condition the creature had, and never with none)
- [ ] **SU-0044** Master of Revenants. Expect: Master of Revenants: each Revenant heals 50% of its Health at the end of its own turn while your party is all Revenants (code healed once per party creature)
- [ ] **SU-0045** Unrealized Potential. Expect: Unrealized Potential: the stat gain is split evenly over two gains (50% + 50%; code halved the copy again, 50% + 25%)
- [ ] **SU-0046** Master of Rift Dancers (deaths). Expect: Master of Rift Dancers on deaths: the extra on-death pass is Dark Dance activating 1 additional time, so it needs Dark Dance on the master's side (code: any all-Rift-Dancer side with the Master)
- [ ] **SU-0047** On-death effects without a death. Expect: Death flags ('cannot be resurrected') apply only to creatures that really died (on-death effects run on a living creature, e.g. Mortal Terror + Feast and Famine, no longer mark it)
- [ ] **SU-0048** Puppet Master. Expect: Puppet Master: +20% damage dealt per minion, as the text says (code added a second +10% per temporary ally); the 5% less damage taken per minion is unchanged
- [ ] **SU-0050** Gambler's Game. Expect: Gambler's Game: otherwise it gains a random trait, as the text says (code gave a random debuff)
- [ ] **SU-0051** Tantalizing Temptation. Expect: Tantalizing Temptation: the forced attack deals 200% normal damage (code 98%)
- [ ] **SU-0055** Redirected attacks (Guardian, Vigilance, Pocket Tank). Expect: Redirected attacks (Guardian, Vigilance, Pocket Tank, Provoke and the other intercepts) are computed with the interceptor's Defense (code: the first target's)
- [ ] **SU-0057** Details Matter. Expect: Details Matter: hits on your creatures end at half of a neutral hit, as if they were strong against the attacker's class (code halved whatever the class step gave, so weak hits ended at a quarter and strong ones at full)
- [ ] **SU-0058** Unbreakable. Expect: Unbreakable: your creatures' Class Strength Artifact properties prevent 50% more damage (code: a flat extra 50% reduction for any creature with an Artifact, property or not)
- [ ] **SU-0059** Time Fracture Resonance. Expect: Time Fracture Resonance: works only while the holder itself is at the bottom of the Timeline (code: any creature of its side)
- [ ] **SU-0064** Careful What You Wish For / Grim Ailment. Expect: Careful What You Wish For / Grim Ailment: buffs on that side / debuffs from that side last 1 turn, as the text says (limit was missing). Needs SU-0080 (shared add-condition hook)
- [ ] **SU-0066** Like Sand (+ Master of Stags). Expect: Like Sand: consumes 2 additional charges, 4 with Master of Stags (code 1 / 3)
- [ ] **SU-0067** Childhood's End. Expect: Childhood's End: enemies take 50% less Bomb damage (code had 40%)
- [ ] **SU-0068** Closure. Expect: Closure: gains 35% Current and Maximum Health (code had 25%)
- [ ] **SU-0069** Peekaboo!. Expect: Peekaboo!: your creatures deal 150% more damage to Invisible creatures (code had +300% holder, +250% side)
- [ ] **SU-0070** Cold Blood. Expect: Cold Blood: deals between 50% and 250% normal damage (code had 175%-300%)
- [ ] **SU-0072** Chastity. Expect: Chastity: Invisible while Health is more than 90% (code had 90% or more, on the cast path)
- [ ] **SU-0073** Shackler's Trance. Expect: Shackler's Trance: 200% more damage when it isn't its turn (code had 100% more)
- [ ] **SU-0075** Blink of an Eye (Nether boss Blacksmith Ianne, traits 1351-1353). Expect: Blink of an Eye (Nether boss Blacksmith Ianne): 10% per hit on tiers 2-3 and a 95% maximum, as its text says (code: 5% and 80%)
- [ ] **SU-0076** Seeth. Expect: Seeth: additional damage = 20% of the damage THIS creature has taken (code used the target's)
- [ ] **SU-0077** The Walking Dead. Expect: The Walking Dead: Zombies use their master's highest stat, Health included (code skipped Health; balance change)
- [ ] **SU-0078** Rodian Aftermath. Expect: Rodian Aftermath: its holder deals 30% more damage per death (code gated it on Oathbreaker, so Rodian Aftermath did nothing and Oathbreaker got the bonus). Confirmed in game
- [ ] **SU-0081** Master of Angels. Expect: Master of Angels: copies Black Hole Halo's Scorned onto your Angels' attacks (code applied Bomb)
- [ ] **SU-0093** Life And Other Illusions. Expect: Life And Other Illusions: effects that activate when creatures attack are ignored whichever side holds the trait (code: only when the opposing side held it)
- [ ] **SU-0094** Madness And Other Ideals. Expect: Madness And Other Ideals: effects that activate when creatures defend are ignored whichever side holds the trait (code: only when the opposing side held it)
- [ ] **SU-0095** Forgiveness And Other Blunders. Expect: Forgiveness And Other Blunders: effects that activate when creatures provoke are ignored whichever side holds the trait (code: only when the opposing side held it)
- [ ] **SU-0096** Love And Other Disasters. Expect: Love And Other Disasters: effects that activate when creatures are afflicted with a buff or debuff are ignored whichever side holds the trait (code: only when the opposing side held it)
- [ ] **SU-0107** Disposability. Expect: Disposability: only your other creatures' buffs persist through death (code: the holder's own buffs and every minion persisted too)
- [ ] **SU-0115** No Head Necessary. Expect: No Head Necessary: each dead holder has its own 50% chance to attack (code: one roll for all)
- [ ] **SU-0123** Xyrxzy's Subversion. Expect: Xyrxzy's Subversion: fires only after the holder's manual casts, so it can't re-trigger itself (code: after every cast, looping to the cast limit)
- [ ] **SU-0146** Better, Faster, Stronger (1989) + Writhelings. Expect: Better, Faster, Stronger: Writhelings afflict a random enemy with a random debuff a second time (code repeated Pleasant Disease's random buff on an ally)
- [ ] **SU-0147** Braze (344). Expect: Braze: your creatures' Class Strength Artifact properties deal 50% more damage (code: a flat +50% of the hit for any creature with an Artifact, property or not)
- [ ] **SU-0148** Colony (84). Expect: Colony: only your living Griffons defend as well (code: dead ones too)
- [ ] **SU-0149** Diabolic Link (243). Expect: Diabolic Link: each Diabolic Horde gets the others' Maximum Health (code also added its own again, so a lone one ended at 50% instead of 25%)
- [ ] **SU-0150** Extra Treat (1036). Expect: Extra Treat: creatures can cast up to 3 times per turn (code's limit let only 2 through)
- [ ] **SU-0151** Filtered Truth (41). Expect: Filtered Truth: enemies always have equal Attack and Intelligence, whichever FINAL value is lower (code compared base fields before bonuses)
- [ ] **SU-0153** Periphery (603). Expect: Periphery: works for the holder's own side, enemy holders included (code: player side only)
- [ ] **SU-0154** Perishing Salvo (1704). Expect: Perishing Salvo: damage = 15% of Intelligence x every Attack stat slot on its Artifact, hybrids included; no Artifact = no damage (code: pure Attack slot only; flat 15% with no Artifact)
- [ ] **SU-0155** Phasers (new finding, not claimed). Expect: Phasers: restores 1 charge to one non-Ultimate gem, for either side (code gave +1 to every gem, player side only)
- [ ] **SU-0156** Pumpkin Spice (333). Expect: Pumpkin Spice: each side with a holder swaps its creatures' Maximum Health and Defense, once (code: only the first holder's side)
- [ ] **SU-0158** Valiant Heart (1924). Expect: Valiant Heart: +1 attack / cast for each other creature with the same secondary Fusion (code: counted itself, and unfused creatures all matched)
- [ ] **SU-0159** Vicar's Blessing (1089). Expect: Vicar's Blessing: one 35% chance per Blight tick, whatever the number of holders (code: one roll per holder)
- [ ] **SU-0160** Grandiose (1982). Expect: Grandiose: the +3 turn counter comes at the end of your creatures' turns, as the text says (code: at the start)
- [ ] **SU-0161** Greybeard's Blessing (1881). Expect: Greybeard's Blessing: your creatures' heals on enemies with Blighted are doubled (code: every heal on them, the enemies' own and Mending included)
- [ ] **SU-0162** Haunting Memories (878). Expect: Haunting Memories: works while its holder is dead, as the text says (code: the trait lookup skipped dead holders)
- [ ] **SU-0163** Horde (141). Expect: Horde: the shared Speed is not applied to creatures that have the trait (code: holders received it)
- [ ] **SU-0164** Kiichi's Aggression (1254). Expect: Kiichi's Aggression: after an enemy takes damage from Bleeding, all other enemies take 50% of the damage it actually took (code: 50% of the pre-reduction Bleed amount)
- [ ] **SU-0165** Kiichi's Persistence (1257). Expect: Kiichi's Persistence: the extra hit is not modified by effects that affect Bleeding (code applied Master of Pilwizes, the Pilwiz cards and other Bleed modifiers)
- [ ] **SU-0166** Master of Arachnalisks (1399). Expect: Master of Arachnalisks: enemies take 20% more Poison damage per Arachnalisk on the holder's side (code boosted Poison on the holder's own side)
- [ ] **SU-0167** Master of Dumplings (1428). Expect: Master of Dumplings: the Dreamsicle (Caliban) skin gets Caliban's Avatar Ultimate, Awakened Nether Orbs (code: a random Ultimate)
- [ ] **SU-0168** Master of Imlers (1449). Expect: Master of Imlers: 20% more damage per Imler / Imling, the attacker included (code left the attacker out)
- [ ] **SU-0169** Master of Manticores (1458). Expect: Master of Manticores: your creatures get +15% Attack and Defense per Manticore (code gave it to Manticores only)
- [ ] **SU-0170** Master of Stags (1501). Expect: Master of Stags: Prism uses 200% of the potency-modifier stats for an all-Stag party with the Master (user ruling: 100% more effective doubles the numbers). Christmas Is Canceled not built
- [ ] **SU-0171** Master of Wolpertingers (1517). Expect: Master of Wolpertingers: the 50% extra Scourge cast can repeat while it keeps succeeding (code: one roll)
- [ ] **SU-0172** Necronomicon (115). Expect: Necronomicon: only the holder's own Death spells act as if it has 50% less Intelligence (code: every Death spell of its side)
- [ ] **SU-0174** Hate And Other Triumphs. Expect: Hate And Other Triumphs: effects that activate when creatures die are ignored whichever side holds the trait (code: only when the opposing side held it)
- [ ] **SU-0175** Justice And Other Fallacies. Expect: Justice And Other Fallacies: effects that activate when creatures are resurrected are ignored whichever side holds the trait (code: only when the opposing side held it)
- [ ] **SU-0176** Touch of Red counts additional attacks, not each attack. Expect: Touch of Red: +25% for each attack in the chain, the first one included (code: each additional attack)
- [ ] **SU-0178** I HATE YOU !@#$ING ALL (Torun). Expect: I HATE YOU !@#$ING ALL works for an enemy holder too: its team Provokes at the end of its turns and takes 90% less damage while Provoking (code: your side only)
- [ ] **SU-0183** Hymn of Panic. Expect: Hymn of Panic: the Timeline is shuffled into a uniformly random order (code: a coin flip into two groups with a fixed order inside each)
- [ ] **SU-0222** Luck re-rolls (Sleight of Hand, Good/Bad Luck, Spin the Wheel). Expect: Spin the Wheel also works for an enemy holder, on your creatures' turns (code: only your holder on enemy turns). Needs SU-0001
- [ ] **SU-0260** Defer Pain. Expect: Defer Pain also delays damage taken during the holder's own turn; only the delayed damage coming back is exempt (code: nothing taken on its own turn was delayed)
- [ ] **SU-0261** Devotion. Expect: Devotion: the 'only one Imler and one Imling' test uses the shared race count, so Odd One, Shackler's Mastery and Forest Pact apply (code: its own count, which ignored them)
- [ ] **SU-0264** Draconic Arrogance. Expect: Draconic Arrogance: reads the other creatures' stored stats, so it no longer crashes the game with From Death to Destiny or Lifeblood (code: computed them, and the two traits recursed)
- [ ] **SU-0267** Emerald Attunement. Expect: Emerald Attunement does not stack: one +50% even when both sides have it (code: +50% per side, +100% with both)
- [ ] **SU-0268** Forbearance + Master of Wights. Expect: Master of Wights + Forbearance: the Wight's 100% Health is the base the resurrection bonuses add to (code: Master of Wights overwrote the bonus with 100%)
- [ ] **SU-0269** Fallen Star. Expect: Fallen Star: 50% for every stat (code: 35% for Defense / Intelligence / Speed), a Feared holder does not steal, and Max Health gains can be stolen too
- [ ] **SU-0270** Father Shadow. Expect: Father Shadow's extra hit follows only damage to an enemy (code: also damage to its own allies)
- [ ] **SU-0271** Gemcutter. Expect: Gemcutter unseals only its own side's Ultimate gems (code: every Ultimate gem on the field when either side has it)
- [ ] **SU-0272** Giftwrapped Army. Expect: Giftwrapped Army gives each Mimic buffs it doesn't already have (code: repeats possible)
- [ ] **SU-0275** Grandiose. Expect: Grandiose (and Redefined): effects that count buffs / debuffs see the +3 (Lenience, Holy Might, Reckoning, Pandemonium Exploit, Under Stress, Swell, Nighttaker, Ruin, Daybreaker, Heresy and two spells) (code: they counted the raw list)
- [ ] **SU-0280** Improbable Catapult. Expect: Improbable Catapult: Avatar traits copied to enemies work for the enemy side (Prayer Position, Avenged Sevenfold, Firelord, Expanded Power, The End, Perfect Imperfection's damage parts, The Truth, The Black, I HATE YOU); code: your side only
- [ ] **SU-0281** Jealousy. Expect: Jealousy: the 'only one Imler and one Imling' test uses the shared race count, so Odd One, Shackler's Mastery and Forest Pact apply (code: its own count, which ignored them)
- [ ] **SU-0286** Master of Hounds. Expect: Master of Hounds: only Hounds' Dire Wolves use the highest stat (code: every Dire Wolf owner on the holder's side)
- [ ] **SU-0289** Master of Spellmanes. Expect: Master of Spellmanes: gems that can't be sealed read as unsealed at once (code: sealed until the gem manager's next pass); also the read side of SU-0212
- [ ] **SU-0290** Mesmer. Expect: Mesmer changes the enemy's class to the holder's class weakness, the class strong against the holder, as Quantum Flux reads the same words (code: the class the holder is strong against)
- [ ] **SU-0297** Ravish. Expect: Ravish hits back only when the damage came from an enemy (code: any source, allies and itself included)
- [ ] **SU-0301** Roulette (new finding: heal branch ends the whole attack). Expect: Roulette: a heal roll ends only that hit (no damage, like a hit that dealt none), so the remaining extra attacks and the after-attack effects still happen (code: the heal roll ended the whole attack)
- [ ] **SU-0303** Savior (new finding: halves damage to itself). Expect: Savior takes half of the damage dealt to your other creatures and no longer halves the damage dealt to itself (code: halved every hit on its side before checking who was hit)
- [ ] **SU-0310** Terminus. Expect: 'Cannot be resurrected' (Burn Their Corpses, Endwalker, Feast and Famine, End On a High Note, Epigraphy, Disintegrating Arrow) also stops resurrections queued before the death (Terminus, Defy the Gods, Reincarnation, Genesis) (code: checked only when queued)
- [x] **SU-0052** Sugar Rush. Expect: Sugar Rush: all of the creature's buffs are removed at the end of its turn (code skipped the buff after each removed one) *(last result: bug confirmed: 1 buff kept after Sugar Rush's end-of-turn removal)*

### Perks

- [ ] **SU-0024** Demonologist vs anointed Undying Loyalty / Eternal Guardian. Expect: Demonologist with anointed Undying Loyalty / Eternal Guardian: minions (UL) and buffs (EG) persist through death as their texts say, demon minions stay; UL + EG together keep both
- [ ] **SU-0060** Windwalker. Expect: Windwalker: 5% avoid chance (up to 80%) for each time ALL your creatures dodged this battle (code counted only the damaged creature's own dodges)
- [ ] **SU-0079** Turn the Tables (Gladiator perk). Expect: Turn the Tables: the attack after casting an Equipment spell deals 50% more damage (code dealt 50% of normal)
- [ ] **SU-0085** Covenant. Expect: Covenant: once your creatures have cast each Rune spell, their on-attack effects activate 1 additional time, only with Covenant (code gave it to any caster without the perk)
- [ ] **SU-0108** True Ending. Expect: True Ending: all on-death effects are ignored except Born Again (code still ran everything above its exit at L163)
- [ ] **SU-0127** Bolster (Hell Knight). Expect: Bolster: less damage from attacks and spells only (code also cut indirect damage)
- [ ] **SU-0128** Born Again (Windrunner). Expect: Born Again: creatures killed by start-of-battle effects (including queued ones like Red Wedding) are resurrected with 50% Health
- [ ] **SU-0129** Double Time (Gladiator). Expect: Double Time: the extra Trick debuff is applied as a debuff (code applied it through the buff event, triggering on-buff effects)
- [ ] **SU-0131** Impending Victory (Gladiator). Expect: Impending Victory: the 50% highest-stat blend also applies to healing and stat Arsenal spells (code: damage spells only)
- [ ] **SU-0132** Life After Death (Purgatorian). Expect: Life After Death: Death's Bite and Sugar and Slice work while their holder is dead (code required a living holder)
- [ ] **SU-0133** Union (Tribalist). Expect: Union: each creature grants its % of Health from its Max Health at battle start, not compounded along the party
- [ ] **SU-0212** Diabolism (Rune Knight) / Straight Up / Unstoppable Force: 'cannot be Sealed'. Expect: Diabolism / Straight Up / Unstoppable Force: their gems read as unsealed at once (code: sealed until the gem manager's next pass). Needs SU-0289 (shared sealed-read hooks) and SU-0137 (cast check)
- [ ] **SU-0216** Forsaken Wonder (Antiquarian): spread. Expect: Forsaken Wonder: the Relic buffs given at the start of battle (Arbiter, Ferro, Prime & Ventus, Salus, Triumvir, Whisper) and Bloodseeker's 'always has' buffs spread to your other creatures and last forever; with Primordial Curse, Blazefury 40's start-of-battle Burning lasts forever (code: no spread, no permanence for these direct adds)
- [ ] **SU-0218** Photosynthesis (Grovetender). Expect: Photosynthesis: buffs and minions your Herbling receives at the start of battle count, like the ones it receives later (code: only in-battle grants counted). Start-of-battle stat gains not built
- [ ] **SU-0219** Sacrifice (Bloodmage) with artifact Health. Expect: Artifact Health %: current and Max Health gain the same amount (code: current Health gained a share of the already raised Max Health, which nearly cancelled Sacrifice)
- [x] **SU-0080** Primordial Curse / Forsaken Wonder. Expect: Primordial Curse / Forsaken Wonder: debuffs inflicted / buffs granted by your creatures' Relics (and Ancient Synchronicity Avatars / Godspawn) last forever; no longer on your own Relic creature *(last result: partial: spread works (unchanged, was never broken); permanence on your own Avatar holding its own god's Relic is gone (fixed); Relic-inflic)*

### Spells

- [ ] **SU-0074** Entropic Swing. Expect: Entropic Swing: all creatures' end-of-turn effects activate (code stopped after the first creature)
- [ ] **SU-0084** Illusion minion. Expect: Illusion minion: +2 Artifact attack rolls when the ATTACKER has Illusion (code tested the target)
- [ ] **SU-0137** Astral Dimension. Expect: Astral Dimension: the gem can't be Sealed (code: nothing implemented it)
- [ ] **SU-0138** Blindside. Expect: Blindside: a small amount of damage based on the caster's Intelligence like other spells (code used Speed)
- [ ] **SU-0139** Corpse Explosion. Expect: Corpse Explosion: small damage x (1 + dead creatures) (code: moderate x dead count, 0 with none dead)
- [ ] **SU-0140** Internal Combustion. Expect: Internal Combustion: when the target is killed, all other enemies take 25% of the damage dealt as a splash (Splashing's form: no second round of spell bonuses or crit, no chaining; kills count for the caster)
- [ ] **SU-0141** Pustule. Expect: Pustule: a small amount of damage based on the caster's Intelligence (code used Defense)
- [ ] **SU-0143** Witchcraft. Expect: Witchcraft: Cursed enemies cast one of their single-target damage spells on a random creature (either side, living, not itself) (code: always hit the caster's opponents)
- [ ] **SU-0226** Chaos Rift (cast by Velox / Lagopus). Expect: Chaos Rift is filed as a utility spell (code: a stat-boosting spell), so Velox / Lagopus / Temptation rank 100 no longer pick it
- [ ] **SU-0228** Dark Ritual (not cast by Velox / Lagopus). Expect: Velox / Lagopus also cast Dark Ritual, a stat-changing spell (code: only BOOST / DEBOOST-tagged gems)
- [ ] **SU-0229** Death Siphon (not cast by Velox / Lagopus). Expect: Velox / Lagopus also cast Death Siphon, a stat-changing spell (code: only BOOST / DEBOOST-tagged gems). Needs SU-0228 (shared tag-test hook)
- [ ] **SU-0233** Ice Bolt. Expect: Ice Bolt always afflicts Frozen (code: only when its damage on the target is above 0)
- [ ] **SU-0234** Memento of Attack / Intelligence / Defense / Speed (while sealed). Expect: Memento of Attack / Intelligence / Defense / Speed: also counts while the gem is Sealed (code: a sealed Memento gave nothing)
- [ ] **SU-0235** Shellbust. Expect: Shellbust deals 150% of the Defense actually lost (code: of the planned loss, even when it is blocked, reflected or turned into a gain)

### Cards

- [ ] **SU-0010** Valkyrie card power 3. Expect: Valkyrie card power 3: enemies have a 75% maximum chance to crit (code capped your creatures' crits instead)
- [ ] **SU-0011** Shapeshifter card powers 2/3. Expect: Shapeshifter card powers 2/3: your creatures take 10% (20%) less damage from attackers strong against their class (code: more damage from attackers weak against them)
- [ ] **SU-0035** Grimoire card refund floater. Expect: Grimoire card refund floater names the Grimoire card set (code showed Apocalypse)
- [ ] **SU-0056** Class cards power 1 (Ophan, Lich, Cerberus, Imp, Occultist). Expect: Class cards power 1 (Ophan, Lich, Cerberus, Imp, Occultist): only 10% more damage (code also cut the target's Defense by 10%)
- [ ] **SU-0242** Smith cards (power 2). Expect: Smith cards power 2 raise only the buff / debuff trick slots' activation chance (code: every trick slot's value by 10%)

### Spell gem properties

- [ ] **SU-0015** Prism + Topaz (damage spells). Expect: Prism + Topaz: damage spells use the caster's Defense as the potency stat (code used the target's)

### Conditions and minions

- [ ] **SU-0033** Confused attackers. Expect: Multi-hit attacks: every hit gets each '% more damage' bonus once (the pool no longer piles up hit after hit); also stops the Confused chance leaking into damage (SU-0033)
- [ ] **SU-0071** Frozen. Expect: Frozen: 25% chance to thaw on the first turn (50% if resistant), doubling after each turn (code started at 50%)
- [ ] **SU-0124** Beelzebub. Expect: Beelzebub: triggers when its master kills an enemy (code: any kill, allies too)
- [ ] **SU-0125** Leviathan. Expect: Leviathan: triggers when its master kills an enemy (code: any kill, allies too)
- [ ] **SU-0126** Spiderlings. Expect: Spiderlings: explode after the master takes damage from an enemy, for 50% of the master's Current Health (code: any sourced hit, allies too; Maximum Health)
- [ ] **SU-0200** Disarmed. Expect: Disarmed: the Artifact's trait, its Nether Stone's traits and the Nether Stone's trick properties are lost too (code: only stats, trick slots and spells were)
- [ ] **SU-0202** Unstable Horror. Expect: Unstable Horror: the damage uses the master's highest stat, Health included (Maximum Health) (code: the second-highest when Health was highest)

### Guilds

- [ ] **SU-0144** Death Guild. Expect: Death Guild: the Debuff Potency bonus is applied once per debuff (code added it once per living party creature, compounding)

### Combat systems and other

- [ ] **SU-0025** Instant kills. Expect: Instant kills: on-death effects also repeat for a Fable rank 80 bearer and Master of Rift Dancers, as damage deaths do
- [ ] **SU-0027** Spell stat calculator. Expect: Spell stat calculator: no damage-only 'ignore Defense' cuts on the caster's own Defense pool (code applied six of them)
- [ ] **SU-0038** Multi-hit attacks. Expect: Multi-hit attacks: every hit gets each '% more damage' bonus once (the pool no longer piles up hit after hit); also stops the Confused chance leaking into damage (SU-0033)
- [ ] **SU-0063** Rune Damage Cap. Expect: False God Damage Cap rune: a hit can't deal more than 5% of Health (code only capped hits above 10%)
- [ ] **SU-0082** Squash realm minigame. Expect: Squash realm minigame: squash2 writes digit 2 (code wrote 0), so all 10 Squash combos can happen like Fruit and Tarot. Playtest-confirmed bug
- [ ] **SU-0088** on-attack relic ranks. Expect: On-attack relic follow-ups ('this relic attacks that target / the enemy'): skipped when the bearer hits its own side (code: a Confused bearer's relic attacked the ally too)
- [ ] **SU-0134** Artifact Spell Slot vs Nether Stone. Expect: Artifact Spell Slot: the artifact's chance starts from its own base (+ Smith), not the chance left over from the Nether Stone's spells
- [ ] **SU-0135** Reliquary "Stat Bonus" upgrade. Expect: Reliquary Stat Bonus: raises the Relic's stats by 1% per rank (100% more with Abandoned Altar) (code: the Relic stat redirect returned before the bonus)
- [ ] **SU-0189** Bosses moved down the Timeline. Expect: Lord Zantai's battle: forced 'move to the bottom of the Timeline' moves him down 1 place, like the other bosses (code: the boss list missed battle type 37)
- [ ] **SU-0204** Realm 'Next battle' boosts in boss and special fights (new finding while decoding B1#52). Expect: Realm 'Next battle' boosts work in the next battle of any kind (code: switched off in boss and special battles but still used up there)
- [ ] **SU-0206** Nemesis: Misery. Expect: Misery (Nemesis): your creatures cannot gain buffs from direct adds either (start-of-battle, 'always has', in-battle direct grants), as from buff events (code: only the buff event refused). Start-of-battle stat gains not built
- [ ] **SU-0243** Teleportation Shrine (choose a Realm Type). Expect: Teleportation Shrine: after paying 1,000 Power the Realm Type choice travels (code: the cost was checked again after paying and failed below 2,000)

## 2. Investigate (code is certain, intent or impact needs a look)

### Combat systems and other

- [ ] **SU-0249** Battle music (Battle Music option OFF: realm music in battle). With Battle Music OFF, the text says the realm music keeps playing in battle. In 17 realms (Death, Sorcery, Forest, Chaos, Life, Dungeon, Island, Desert, Underwater, Space, Foreign, Jungle, Void, Reac Test: see the bug record
- [ ] **SU-0307** Skyttels: Save & Restart crash. The community says that after Skyttels copies enchanted gems, "Save & Restart" crashes the game when it restarts (the save itself completes). No static path from Skyttels to the save data exists in th Test: see the bug record

## 3. Text corrections

First check once: one corrected description shows the new text, and a description from the same file
that was NOT corrected still shows its normal text (the override must add to the game text, not replace it).

## 3. Text corrections (each)

### Traits

- [ ] **SU-0173** `L_TRAIT_NAME_CHROMA'SINSTABILITY` (traits.csv) should read: "Chroma's Stability"
- [ ] **SU-0182** `L_TRAIT_DESC_COVERT` (traits.csv) should read: "Your creatures' {TIMELINE} placement at the start of battle is determined by their {STAT_attack} rather than their {STAT_speed}. Prepared takes priority over this trait."
- [ ] **SU-0182** `L_TRAIT_DESC_SURPRISE!` (traits.csv) should read: "This creature always starts battle at the top of the {TIMELINE}, unless an effect places it at the bottom."
- [ ] **SU-0192** `L_TRAIT_DESC_OBELISK` (traits.csv) should read: "Your creatures' [temporary] Ethereal Spell Gems have the same number of {STAT_charges} they'd have if they weren't Ethereal. Copies created by Generous still have only 1 {STAT_charge}."

### Perks

- [ ] **SU-0036** `L_P_DOMINATION` (perks.csv) should read: "Domination"

### Spells

- [ ] **SU-0191** `L_CODD_SPELLGEMS_SPELL_POTENCY` (codex.csv) should read: "is used for each tier of potency. Spells that affect an entire party use 25% of these amounts."
- [ ] **SU-0193** `L_ID_DUST_BERYL` (items.csv) should read: "for each of the same Spell Gem equipped by your party."

### Spell gem properties

- [ ] **SU-0121** `L_ID_DUST_AQUAMARINE` (items.csv) should read: "This item can be taken to the Enchanter to add the following property to your Spell Gems:\n\nCascading: the spell's potency is increased by 5% for each Charge the Spell Gem is missing."
- [ ] **SU-0122** `L_ID_DUST_AVENTURINE` (items.csv) should read: "This item can be taken to the Enchanter to add the following property to your Spell Gems:\n\nSingular: the spell's potency is increased by 50% for each empty Spell Gem slot the creature has."

### Combat systems and other

- [ ] **SU-0180** `L_CODD_CREATURES_CLASSES` (codex.csv) should read: "is strong against that of the enemy. For spells, the Spell Gem's class is used instead of the caster's."

