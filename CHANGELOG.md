<!---
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: CC-BY-NC-ND-4.0
-->

## Verifpal 0.7.5
*October 19, 2019*

- Fixes to analysis logic.
- Compiled with Go 1.13.3.

## Verifpal 0.7.4
*October 17, 2019*

- Compiled with Go 1.13.2.

## Verifpal 0.7.3
*October 14, 2019*

- Improve analysis performance speed.

## Verifpal 0.7.2
*October 9, 2019*

- Fixes to analysis logic.

## Verifpal 0.7.1
*September 29, 2019*

- Fix passive attacker analysis not initializing on some models.

## Verifpal 0.7.0
*September 22, 2019*

- More work on spotting missed attacks.

## Verifpal 0.6.9
*September 21, 2019*

- Build upon the refactoring made in 0.6.8, with a focus on addressing missed attacks.

## Verifpal 0.6.8
*September 17, 2019*

- Major refactor of analysis logic. Missed attacks in more complex models should be expected. However, Verifpal's behavior is now significantly more correct, more complete, and analysis speed has increased dramatically.

## Verifpal 0.6.7
*September 14, 2019*

- Fixes to analysis logic.

## Verifpal 0.6.6
*September 13, 2019*

- Fixes to sanity check order.

## Verifpal 0.6.5
*September 13, 2019*

- Fixes to analysis logic.

## Verifpal 0.6.4
*September 12, 2019*

- Fixes to analysis logic.

## Verifpal 0.6.3
*September 11, 2019*

- Fixes to analysis logic.

## Verifpal 0.6.2
*September 10, 2019*

- More improvements to analysis logic.

## Verifpal 0.6.1
*September 10, 2019*

- Fixes to analyis logic.

## Verifpal 0.6
*September 9, 2019*

- BREAKING: `HMACVERIF` has been renamed to `ASSERT`.
- BREAKING: `HMAC` has been renamed to `MAC`.
- Reduced the number of false positives.

## Verifpal 0.5
*September 8, 2019*

- Increased analysis speeds by only mutating relevant values.
- Fixed even more parsing errors pointed out by Mike.

## Verifpal 0.4.4
*September 8, 2019*

- NEW: `nil` keyword. Self-explanatory (by popular request).
- NEW: `_` can be used to assign anonymous constants (by popular request).
- Fix yet more parsing errors pointed out by Mike.
- More fixes and improvements to authentication queries.
- Added a new hopefully instructional example model: `ephemerals_and_signature.vp`

## Verifpal 0.4.3
*September 7, 2019*

- Fix more parsing errors pointed out by Mike.
- More fixes and improvements to authentication queries.
- More accurate ProtonMail model. 

## Verifpal 0.4.2
*September 7, 2019*

- Fix parsing errors pointed out by Mike.
- More fixes and improvements based on feedback from Loup Vaillant and Sasha Lapiha.
- Authentication queries where constant is unused by recipient are now invalid.
- Fixed a crash reported by Renaud Lifchitz.
- Small general improvements.

## Verifpal 0.4.1
*September 4, 2019*

- More fixes and improvements to authentication queries.

## Verifpal 0.4
*September 3, 2019*

- EXPERIMENTAL: Tampering detection in authentication queries.
- Allow attacker to decompose AEAD_DEC without knowledge of AD, only of key.
- Improved accuracy of bundled Scuttlebutt model.
- Fixed newlines on result printing (thanks to Loup Vaillant.)

## Verifpal 0.3
*August 29, 2019*

- Fix: terminate on extremely tiny and simple models.
- Fix: capitalize generator constant in pretty-printing.

## Verifpal 0.2
*August 27, 2019*

- Correctly pretty-print guarded constants.

## Verifpal 0.1
*August 26, 2019*

- Initial alpha release.
