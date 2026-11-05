# HUCTF 2026 — Hofstra University Capture the Flag

**Cybersecurity competition write-up | October 2026**  
**Focus:** Web exploitation · Cryptography · Binary exploitation · Digital forensics · Reconnaissance

## Overview

I participated in HUCTF 2026 and worked through hands-on security challenges using a browser, Kali Linux, terminal tools, and Python. This repository documents my investigative process, selected screenshots from the event, what I confirmed, and what I learned. Not every challenge below was completed; I distinguish verified outcomes from exploratory attempts.

> **Scope:** All testing described here was performed against competition-provided challenge environments. Screenshots are my original competition notes. The challenge hosts may no longer be available.

## Challenge summary

| Challenge | Category | Documented result |
|---|---|---|
| Front Desk | Web reconnaissance | **Solved** — correct submission shown |
| NoteVault | IDOR / access control | **Confirmed** other users' notes accessible by changing IDs; final flag not documented |
| Network Toolbox | Command injection | Explored pinger input; successful exploit not documented |
| Personalized Greeter | Server-side template injection | **Confirmed** expression evaluation and flag display in screenshot |
| Relay Race | Web navigation | **Completed** eight-step chain and reached flag page |
| Proof Vault | Proof of work / SHA-256 | Generated a nonce in terminal; accepted submission not documented |
| Textbook Secrets | RSA cryptography | Derived cube-root approach; screenshot shows incorrect submission; success not confirmed |
| Event Badge | File forensics | Inspected PNG metadata and trailing-data warning; extraction not documented |
| Member Portal | JWT authentication | Analyzed token-header trust risk; exploit not confirmed |
| Winner's Circle | Binary exploitation | Investigated ret2win buffer overflow; success not confirmed |
| Badge Printer | Format-string exploitation | **Recovered flag** from stack values |
| The Maze | Client-side logic | Investigated browser-side checker; screenshot shows a flag-like result |

## 1. Front Desk — Source inspection and reconnaissance

The challenge encouraged inspecting the page source and common site files. I viewed the HTML and followed a hidden clue to an otherwise undisclosed page. The screenshot shows a flag page, and the challenge interface reports **Correct**.

![Front Desk accepted submission](images/screenshot-01.jpg)
![Hidden reconnaissance result](images/screenshot-02.jpg)
![HTML source inspection](images/screenshot-03.jpg)

**Takeaway:** Comments, exposed paths, and other information in publicly delivered HTML can reveal unintended application details. Sensitive information must not be embedded in client-accessible source.

## 2. NoteVault — Insecure Direct Object Reference (IDOR)

The application linked my note at `/note/1337`. I changed the numeric ID to see whether the server enforced object ownership. My notes record:

| ID | Observed response |
|---|---|
| 1334 | 404 — no note |
| 1335 | Another user's note (Mallory) |
| 1336 | Another user's note (Trent) |
| 1337 | My guest welcome note |
| 1338 | 404 — no note |

The ability to read other owners' notes by changing an ID demonstrated broken object-level authorization. I did **not** record a final flag for this challenge.

![NoteVault challenge](images/screenshot-04.jpg)
![NoteVault guest note](images/screenshot-06.jpg)

**Mitigation:** Check authorization for each object on every request, regardless of whether its identifier is predictable.

## 3. Personalized Greeter — Server-side template injection (SSTI)

The greeting application inserted user input into a server-rendered template. I tested an arithmetic template expression, `{{7*7}}`, and observed evaluated output rather than literal text. A later screenshot shows a flag-like value rendered in the greeting, supporting successful exploitation of the challenge environment.

![Greeter input and evaluated expression](images/screenshot-11.jpg)
![Greeter with flag result](images/screenshot-12.jpg)

**Mitigation:** Treat input as data rather than template source, and avoid evaluating user-controlled template expressions.

## 4. Relay Race — Following an eight-hop chain

Each page supplied a six-character code for the next path, `/r/<code>`. I followed the sequence across eight steps and reached a **chain complete** page with a flag.

![Relay Race challenge](images/screenshot-13.jpg)
![Step 1](images/screenshot-14.jpg)
![Step 8](images/screenshot-21.jpg)
![Chain complete](images/screenshot-22.jpg)

**Takeaway:** Careful observation, accurate URL navigation, and documenting intermediate steps matter even in challenges without an exploit payload.

## 5. Badge Printer — Format-string vulnerability

This was one of my clearest technical wins. The 64-bit Linux program printed user-controlled input as a format string. I tested positional `%p` specifiers to inspect values on the stack. Positions 22–25 exposed hexadecimal fragments of the flag.

```text
%20$p|%21$p|%22$p|%23$p
```

The recorded output began:

```text
(nil)|(nil)|0x6d667b4654435548|0x6633625f72747374
```

Because x86-64 is little-endian, I reversed each eight-byte value's byte order before decoding the bytes as ASCII. The recovered flag was:

```text
HUCTF{fmtstr_b3f8242b8703}
```

![Badge Printer challenge](images/screenshot-35.jpg)
![Stack inspection output](images/screenshot-36.jpg)
![Additional stack positions](images/screenshot-38.jpg)

**Root cause:** A call resembling `printf(user_input)` interprets attacker-controlled formatting tokens. A safer pattern is `printf("%s", user_input)`.

## 6. Textbook Secrets — RSA with e = 3 and no padding

The challenge supplied RSA values `n`, `e`, and `c` and described a short plaintext with `e = 3` and no padding. If `m³ < n`, then `c = m³` without modular wraparound, so recovering the integer cube root of `c` reveals `m`.

```python
from sympy import integer_nthroot
from Crypto.Util.number import long_to_bytes

# Replace with values supplied by the competition service.
c = int("PASTE_C_HERE")
m, exact = integer_nthroot(c, 3)
if exact:
    print(long_to_bytes(m))
else:
    print("Not an exact cube")
```

My notes document this method and a candidate flag, but the screenshot of my submission says **Incorrect**. I therefore do not claim a confirmed solve.

![RSA challenge](images/screenshot-26.jpg)
![Local Python work](images/screenshot-27.jpg)

**Takeaway:** Textbook RSA without secure padding can expose short plaintexts even without factoring the modulus.

## 7. Event Badge — PNG forensic inspection

I used `exiftool` to inspect `badge.png`. The terminal output flagged **minor trailer data after the PNG IEND chunk**, consistent with the challenge hint that data might exist beyond the image. My notes do not include a completed extraction or flag.

![Event Badge challenge](images/screenshot-28.jpg)
![Metadata inspection](images/screenshot-29.jpg)

**Takeaway:** Image forensics includes checking file structure and trailing bytes, not just visible pixels.

## 8. Other investigations

- **Proof Vault:** Investigated a SHA-256 proof-of-work requirement of 20 leading zero bits and generated a candidate nonce with Python; no accepted claim is recorded.
- **Member Portal:** Examined a JWT-based guest session and an admin-only route. The challenge pointed toward header-based key selection, but I did not document a working bypass.
- **Network Toolbox:** Examined an administrative network pinger that constructed commands from input. The provided evidence does not establish successful command injection.
- **Winner's Circle:** Explored a 64-bit ret2win challenge with no stack canary or PIE and a printed `win()` address; no confirmed exploit is documented.
- **The Maze:** Investigated a client-side checker; the screenshot records a flag-like output, but no accepted submission is shown.

![Proof Vault](images/screenshot-23.jpg)
![Member Portal](images/screenshot-30.jpg)
![Winner's Circle](images/screenshot-31.jpg)
![The Maze](images/screenshot-40.jpg)

## Tools and concepts practiced

**Tools:** Kali Linux, browser developer tools / page source, Python, terminal, `nc`, `exiftool`.  
**Concepts:** Reconnaissance, broken access control, SSTI, format strings, stack memory, little-endian decoding, RSA, SHA-256 proof of work, JWT trust boundaries, binary exploitation, file metadata.

## Reflection

HUCTF helped me move from recognizing vulnerability names to testing hypotheses and interpreting real output. The Badge Printer challenge especially reinforced how memory representation and unsafe formatting functions can turn a small programming mistake into an information disclosure vulnerability. The IDOR and SSTI challenges showed the importance of enforcing security controls on the server, not trusting client-visible identifiers or untrusted input. I also learned to document unsuccessful attempts alongside confirmed results, because the troubleshooting process is part of security analysis.

---

*Screenshots and observations are from my HUCTF 2026 challenge notes. This is an educational competition write-up, not a claim that every listed challenge was solved.*
