# Word lists

The watchman's own word lists, written for it (27 Oct 2026) and licensed with it
(Apache-2.0). The first version used the `foul_language.voc` lists of
[ovos-good-manners-pipeline-plugin](https://github.com/OpenVoiceOS/ovos-good-manners-pipeline-plugin);
those are made for bad manners in speech and mix swearing, insults and sexual words,
so these were written instead, in two kinds that match the core's warning labels:

| File | Label | What is in it |
|------|-------|---------------|
| `profanity-<lang>.txt` | `profanity` | Swearing, oaths and vulgar words: *lort, for fanden, fuck, scheiße, merde, joder, cazzo* |
| `sexual-<lang>.txt` | `sexual` | Sexual and obscene words: *kneppe, porno, knulla, ficken, salope, tette* |
| `false-friends.txt` | - | Words that are rude in one language and ordinary in another: they count only in posts in the language of the list that names them |

Languages: `da` `no` `sv` `de` `nl` `en` `fr` `es` `it`.

**Not on them, on purpose:**

- **Insults** ("idiot", "tosse", "Schabracke"): rude behaviour towards a person, not a
  kind of language; harassment is a report reason for people to judge.
- **Words with a harmless meaning in the same language** (German *Schwanz*, a tail;
  *Muschi*, a cat; Spanish *polla*, a chick; Danish *bolle*, a bun): better a missed
  label than a wrong one.
- **Slurs**: there is no warning label for them; hate aimed at people is a report reason.

**Format:** one word or phrase per line, lower case, `#` starts a comment. Only whole
words and whole phrases match. Add inflected forms as their own lines.

**Changing them:** a pull request with the word, the language and - for a false
friend - the language where it is ordinary. Tried on 2400 Usenet posts in six groups
(dk.politik, de.soc.politik.misc, alt.politics, uk.politics.misc, comp.os.linux.misc,
alt.test): profanity on 0-1.2 % of posts, no false hits found.
