# Design kit

The dashboard's visual rules. The living version is the kit page: run `make dashboard` and open
http://localhost:5173/?kit. It renders the real components from `dashboard/src/panels.tsx`, in every state, with
made-up data, and never contacts the gateway. If this file and the kit page disagree, the kit page (the code) wins.

## Direction

The dashboard looks like the front panel of the approval key: warm graphite like an equipment case, plates you press,
indicator lamps for status, and the key's backlit LCD wherever the gateway shows text a person must approve. That
LCD is the signature element: on the key the same words are paged 16 by 2; on the dashboard they sit on one wide
display. Hazard striping appears in one place only, the freeze banner.

## Rules

1. **Flat surfaces.** No glow, no blurred glass, no background gradients. Depth comes from three surface steps and
   hairlines. The one gradient is the hazard stripe.
2. **Colour means something.** Hue is reserved for risk and state. Everything else is graphite and ink. There is
   no decorative accent colour; the primary button is an ink plate.
3. **Plates, not pills.** One corner radius, 2px. Tags are stamps.
4. **Sentence case.** Titles are written like sentences. No tracked-out uppercase labels; machine values (times,
   ids, action types, states) are set in mono instead.
5. **One loud thing.** A pending approval and a freeze dominate the screen. Panels share one weight.
6. **Meaning never by colour alone.** Every risk tier has an icon and a name, and REVERSIBLE is dashed. The tier
   colours follow Okabe-Ito so they hold up for red-green colour blindness.

7. **Readable secondary text.** Text is at least 4.5:1 on the surface it sits on. Secondary text (panel subtitles, hints, the "Expect:" line, blurbs) is at least 13 px (`--fs-s`); machine values (timestamps, ids, action types) at least 12 px (`--fs-xs`); body text 14 px. Nothing is set below 12 px. The kit page's "Text contrast" table is computed from the tokens, so a change that drops below 4.5:1 shows up red there.
8. **Status words say what they mean.** The agent lamp reads IDLE (grey: nothing is running), RUNNING (blue, blinking) or FROZEN (red). Green is for "ok" states such as a connected link, never for "nothing happening". A missing optional part is a neutral note, not an error: with no key attached the lamp reads `key NONE ATTACHED` in grey.

## Tokens

All in `:root` at the top of `dashboard/src/styles.css`; components use only these.

| Group | Tokens | Use |
|---|---|---|
| Surfaces | `--surface-0` to `--surface-3`, `--rule`, `--rule-strong` | page, panels, cards and inputs, hover; hairlines and control borders |
| Ink | `--ink`, `--ink-2`, `--ink-3` | text, secondary text, labels and timestamps (`--ink-3` is at least 5:1 on every surface, hover included; the kit page measures it live) |
| Signature | `--lcd-bg`, `--lcd-ink` | the key's LCD. Yellow-green by default; swap both for a blue-backlit module |
| Risk | `--risk-safe`, `--risk-reversible`, `--risk-external`, `--risk-stop` (aliases `--ok`, `--warn`, `--bad`) | tiers and states only |
| Type | `--sans` (IBM Plex Sans), `--mono` (IBM Plex Mono), `--fs-xs` 12 to `--fs-xxl` 28 | people read sans; machines' values are mono |
| Space | `--s1` 4, `--s2` 8, `--s3` 12, `--s4` 16, `--s5` 24, `--s6` 32 | nothing in between |
| Shape | `--radius` 2px | everything |

IBM Plex is bundled through `@fontsource` (installed by `make setup`), so the dashboard looks the same with no
network.

## Layout behaviour

- **The timeline is the main panel.** It is the wide left column, as tall as the window, directly under the header. The frozen banner (full width) sits above the grid; the approval tray sits directly above the timeline. Everything you set or check (task launcher, autonomy, outbox, recovery points, standing tasks) is a narrower column on the right. While nothing is waiting for an answer the timeline stays pinned in view as the side column scrolls; a pending approval pushes it down and scrolls with the page. Below 900 px the columns stack, timeline first.
- **A pending approval and a freeze are the loudest things on the page.** The approval card has a 2 px amber border and a 10 px left bar, the gateway's summary on the LCD at 20 px, the tier badge, the countdown with a 5 px bar, and large Approve and Deny plates. The banner has a 20 px title and reason and large buttons. Every control shows a 3 px focus ring with a gap when reached by keyboard (the kit page forces it on in one row).
- **Sandbox view.** In mock mode there is no live view, so it is one slim line at the top of the side column. In Docker mode it is the live noVNC view at the top of the side column.
- **Recovery points** show the time, the tier (icon and name) and the action type; identical neighbouring entries (same type and same label) fold into one row with a count, which restores the newest.
- Panels never squeeze each other; when they do not fit, the page scrolls.
- Outbox, Recovery points, Timeline (and the live Sandbox view in Docker mode) resize from the grip on their bottom edge: drag it, or focus it
  and use the arrow keys; double-click resets. Sizes are remembered in this browser only (the kit page keeps its own).
- The Standing tasks panel (off by default; the kit page shows it off, empty, and with tasks enabled, running, paused by a person, paused after three failures and paused by a freeze) lists each task with its next run, last result and state, and has a create form. A new task starts paused. Task text is untrusted: it is capped and rendered as plain text only.
- The task launcher has two tabs, **Clean task** and **Attack task**, and a separate **Run with** switch
  (Scripted agent or Claude). Each task says what to expect. Claude gets a prompt naming the same page, which you
  can edit; it is off without `ANTHROPIC_API_KEY` on the gateway host.

## Changing it

Change a token, then check the kit page: every component that uses it changes there at once. A new component goes
into the kit page in all its states (normal, hover, disabled, alert, empty) before it is used in the app. Keep the
class names, button labels and ARIA labels that `gateway/scripts/dashboard_shots.py` relies on.

## What was checked

`npm run build` (type check and bundle) passes. `gateway/scripts/dashboard_shots.py` drives the dashboard in Chrome against live mock gateways (27 checks, the original ones, all passing). `dashboard_shots.py --ui-shots before|after` takes screenshots of five states (idle, a pending approval at Supervised, the frozen banner, a finished attack run with its HARD_STOP row, an enabled standing task) at 1440 and 1024 px wide into `docs/screenshots/ui-before/` and `ui-after/`, and checks that nothing overflows at either width, including the kit page, and (after) that the timeline is the widest panel and starts near the top. The new states are on the kit page (header lamps, the slim sandbox note, folded recovery points, forced focus rings, the contrast table, the layout sketch). Not run: other browsers, phones, a screen reader, a person using it.
