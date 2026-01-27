# Test Coverage Analysis

## Current State: 0% Coverage

No test files, no test framework, and no test configuration exist in this codebase.

## Codebase Summary

| Module | File | Lines | Coverage |
|--------|------|-------|----------|
| Server | `index.js` | 12 | 0% |
| Onboarding | `src/pages/Onboarding.jsx` | 138 | 0% |
| Chat | `src/components/Chat.jsx` | 113 | 0% |
| Moderation | `src/components/Moderation.jsx` | 0 | Empty stub |
| MatchCard | `src/components/MatchCard.jsx` | 0 | Empty stub |
| ConsentModal | `src/components/ConsentModal.jsx` | 0 | Empty stub |
| App | `src/App.jsx` | 0 | Empty stub |
| Home | `src/pages/Home.jsx` | 0 | Empty stub |
| main | `src/main.jsx` | 0 | Empty stub |

## Priority Areas for Test Improvement

### Priority 1: Onboarding Component

The most complex component (138 lines) with multi-step form logic.

Tests needed:
- Step progression (steps 1-4)
- Form state toggling for checkboxes, radios, selects
- Data submission (POST to `/api/me`, auth headers, stats tracking)
- `onDone` callback invocation after save
- Edge cases: toggling items, empty selections, missing token

### Priority 2: Chat Component

Real-time messaging with NVC assist mode (113 lines).

Tests needed:
- Message polling (3-second interval via useEffect, cleanup on unmount)
- Sending messages (empty prevention, NVC formatting, POST, input clearing)
- Rendering (sender/receiver alignment, timestamps, empty state)
- Auth (localStorage token in headers)
- Error handling (fetch failures)

### Priority 3: Backend Server

Minimal server (12 lines) but should still be tested.

Tests needed:
- GET / returns 200 with correct body and content-type
- PORT environment variable override
- Server binds to 0.0.0.0

### Priority 4: Stub Components

Once implemented, each needs full test coverage:
- Moderation.jsx — content moderation rules, flag/report flows
- MatchCard.jsx — profile display, like/pass interactions
- ConsentModal.jsx — consent display, acceptance state
- App.jsx — routing, global state, auth flow
- Home.jsx — dashboard, match list, navigation

## Recommended Setup

- **Framework**: Vitest
- **Component testing**: React Testing Library
- **HTTP testing**: Supertest
- **Coverage target**: 80%+ on critical paths
- **CI/CD**: Run tests on every commit, block merges below threshold
