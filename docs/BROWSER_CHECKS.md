# Working browser verification

The application was exercised locally on macOS with Python 3.12, through the actual browser UI and fictional demo data. These screenshots show the working product, not generated mockups.

- Loaded the fictional sample and saved six masks across eight lines.
- The raw input field cleared; saved output retained timestamps and receipt context.
- Downloaded the actual export and verified it exactly matches the expected redacted fixture output.

All six apps were checked at a 390×844 viewport; this app's document width was 390px with no horizontal overflow. The temporary viewport was reset after the check. The fresh final app load reported no JavaScript errors. Desktop and mobile captures can show different points in the walkthrough.

Automated regression suite: **59 passing tests**. The README describes test scope and measured coverage. These checks do not establish production scale or complete security coverage.
