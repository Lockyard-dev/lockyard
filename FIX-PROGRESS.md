0 not mine
1 not mine
2 not mine
3 not mine
4 fixed
5 fixed, not run
6 fixed
7 fixed
8 fixed, not run: regression test added; socket tests are blocked by sandbox permissions
9 fixed, not run
10 fixed
11 duplicate of 8
12 fixed, not run: tool writes under held claims report dirty paths directly; claim output shows foreign dirty work
13 fixed, not run: hooks fetch session events and acknowledge only after writing them; socket suite is sandbox-blocked
14 fixed
15 not mine
16 fixed
17 fixed, not run
18 duplicate of 7
19 not mine
20 not mine
21 not mine
22 not mine
23 not mine
24 not mine
25 not mine
26 duplicate of 13
27 duplicate of 10
28 not mine
29 fixed
30 not mine
31 duplicate of 7
32 not mine
33 not mine
34 not mine
35 not mine
36 open: unsupported evidence targets are rejected at creation (regression test passes); owner-close is still impossible without a server endpoint
37 not mine
38 not mine
39 fixed, not run
40 not mine
41 fixed
42 not mine
43 not mine
44 not mine
45 not mine
46 not mine
47 not mine
48 fixed
49 not mine
50 not mine
51 not mine
52 not mine
53 not mine
54 not mine
55 not mine
56 not mine
57 not mine
58 fixed
59 not mine
60 fixed, not run: bounded nonblocking connect and backlog regression test added; socket tests are blocked by sandbox permissions
61 fixed
62 fixed
63 not mine
64 not mine
65 not mine
66 not mine
67 not mine
68 not mine
69 not mine
70 open: timed-out inbox claims can outlive the hook deadline; releasing their server-side lease requires an endpoint the protocol does not provide. Claims remain direct and never enter the outbox.
71 not mine
72 not mine
73 not mine
74 implementation updated: token trust applies to direct clients and agent startup; trust command is tested, while fake-server token regression is blocked by sandbox networking
75 fixed and tested: hook and message output preserve Unicode while escaping controls
76 implementation and regression test added: event polling/cache; daemon socket tests are blocked by sandbox permissions
77 implementation and regression test added: dirty reports use the outbox once per claim path; daemon socket tests are blocked by sandbox permissions
78 implementation and regression test added: 403 session ownership is surfaced without renaming the session; HTTP test is blocked by sandbox listener permissions
79 implementation and regression tests added: 429 responses retain Retry-After for writes and event waiters; HTTP tests are blocked by sandbox listener permissions
80 regression test updated: body-free bus.unread events refresh the addressed session's cached unread count; daemon socket test is blocked by sandbox permissions
81 implementation and regression test added: seen counts only IDs the server marked, skipping expired IDs; HTTP test is blocked by sandbox listener permissions
82 implementation and regression test added: bulk release options use the DELETE body and fences require one live claim; HTTP test is blocked by sandbox listener permissions
83 regression test added: bus export/import preserves seen_by and board expires_at; HTTP test is blocked by sandbox listener permissions
84 implementation and regression tests added: registry create/import validate text and evidence size/count limits before sending; HTTP test is blocked by sandbox listener permissions
85 implementation and regression test added: zone requests list from /api/v1/zones/requests for the active session; HTTP test is blocked by sandbox listener permissions
