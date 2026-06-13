# Storytelling Style — Code Guardian Defense

A light **Steve-Jobs arc** for the talk. This is the rulebook the `SPEAKER_NOTES.md` voice follows. Use it when you rehearse, and when you edit any slide, to keep the whole talk sounding like one story instead of 25 separate updates.

> **The one rule:** the story is the *scaffold*; the numbers are the *proof*. Never let the showmanship outrun the evidence. This is a defense, not a keynote.

---

## 1. The spine — villain → hero → twist → callback

Every Jobs talk is one story with four beats. Ours:

- **Villain** — a false choice: *"send your code off your machine, or work almost unprotected."* Plant it on **slides 2–3**.
- **Hero** — three words on **slide 4**: **local, grounded, in the developer's hands.** Say them as a triplet.
- **Twist** — **slide 16**: RAG was supposed to help everywhere. It didn't. Let the surprise land.
- **Callback** — **slide 21** and the **close (slide 25)**: name the false choice again, then say Code Guardian *refuses* it.

If a slide doesn't move one of these beats forward, it's a *proof* slide — keep it tight and factual (see §5).

---

## 2. The sentence-level sweet spot

Jobs did **not** write long sentences. He also didn't write fragments. He wrote **short, complete, declarative sentences** with a build and a payoff.

There are three lengths. Only one is right. Here is the exact evolution Slide 9 went through:

**❌ Too short (telegram — a list of fragments):**
> "Stage one is detection. A JSON-mode LLM call with a fixed schema. Optional RAG context — the top-k retrieved CWE or OWASP snippets. Two passes, different random seeds. Findings kept only on agreement."

Reads like bullet points spoken aloud. Choppy. No rhythm.

**❌ Too long (run-on — clause-heavy):**
> "The extension sends the code to the local model as a single JSON-mode call, with a fixed schema the model has to fill in — so the answer comes back as structured data, not free text."

Proper grammar, but the breath runs out. The point gets buried mid-clause.

**✅ Sweet spot (short complete sentences that build):**
> "Stage one is detection. The code goes to the local model as one JSON-mode call — the model fills in a fixed schema, so what comes back is structured data, not an essay. … Then detection runs twice, each pass from a different random seed. And a finding survives only when both passes agree."

Each sentence stands on its own. You can pause after any of them. It still says everything the telegram said — just so it lands.

---

## 3. The five Jobs moves

Use these deliberately. Each is already in the notes; this is where to reach for them.

1. **Rule of three.** Group ideas in threes and count them out — *"One… two… three."* The ear remembers triplets. (Slide 2 problems, slide 4 properties, slide 5 questions, slide 20 takeaways.)
2. **Headline, then proof.** Open a results slide with one plain sentence, *then* the number — never the reverse. "A local 8B model is enough." *(beat)* "Seventy-one percent F1."
3. **Plant and call back.** Say the spine line on slide 3, then again on 21 and at the close. Repetition is not a mistake — it's the structure.
4. **The reveal line.** End a mechanism with a turn the audience didn't see coming. Slide 9: *"And notice what didn't happen in any of that. Nothing left the machine."*
5. **The pause.** After every headline number, stop. Silence reads as confidence. Let them absorb the percentage before you move.

---

## 4. The twist deserves special care (slide 16)

This is the one genuine plot turn in the talk. Don't flatten it into another results slide.

- Set the expectation first: *"The plan was simple — switch RAG on, get better detection, across the board."*
- Break it: *"And codellama — minus 29.89 F1. The single biggest effect in the whole study — pointing the wrong way."*
- Pause. Then test it: *"So the question is: is it real? … It's real."*
- Land the new lesson: *"RAG is not a free upgrade. It's a per-model choice."*

Slow down here more than anywhere else. The surprise is the argument.

---

## 5. What NOT to dramatize

Jobs let the proof slides breathe. So do we. **Keep these tight and factual — no story flourishes:**

- **Slides 13, 15, 17, 18, 19** — the number-dense results. One headline, then the numbers, then stop.
- Limitations (slide 22) and future work (slide 23) — plain and honest, not performed.
- Never invent a flourish that the data doesn't support. A reveal line must reveal something *true*.

---

## 6. Quick self-audit — run this on any slide

- [ ] Does it move a spine beat (villain / hero / twist / callback), or is it a proof slide? Tighten accordingly.
- [ ] Are the sentences **short and complete** — not fragments, not run-ons? Read it aloud in one breath each.
- [ ] Is there a **headline before the number**, not after?
- [ ] Is there one line worth **pausing** after?
- [ ] On a results slide: did I resist the urge to dramatize, and just let the number land?

---

## 7. Tone guardrails (carried from SPEAKER_NOTES.md)

- **Plain English.** "Stage one is detection," not "the first stage performs the detection task."
- **No first person plural.** Say "the thesis" or "Code Guardian," never "we built." First-person "I" is fine — it's your work.
- **Direct address ("you") is the main Jobs lever** — it puts the panel in the developer's seat. Dial it back if the panel is very formal.
- **Don't apologise. Don't say "good question."** Just answer.
- **Numbers are exact, always.** F1 71.43, repair 90.32, latency 2.2 s, leakFreeRate 100. Story bends the framing, never the figure.
