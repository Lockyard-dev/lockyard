# Two agents, one folder

Alice and Bob are two coding agents in the same repository. Both want `src/api`. Lockyard lets one
of them have it and tells the other why not, instead of letting them overwrite each other.

```sh
cargo build --release -p lockyard
PATH="$PWD/target/release:$PATH" sh examples/two-agents/run.sh
```

The script makes a throwaway project in a temporary folder and deletes it on the way out; nothing
touches the repository you ran it from. With `--check` it also fails if any step behaves differently
from the transcript below, which is how CI keeps this page honest.

## The transcript

```
A new project
$ lockyard init
Lockyard project at /tmp/tmp.2CXLY7oyCZ

Alice takes src/api
$ alice zone claim src/api --note rewrite the routes
Z-1  alice  src/api  30 min left  rewrite the routes

Bob wants a file inside it, and is refused
$ bob zone claim src/api/routes.rs --note fix the 500 on POST
src/api/routes.rs is held by alice through src/api (Z-1): rewrite the routes

Bob asks whether he may touch it at all
$ bob zone check src/api/routes.rs
src/api/routes.rs is held by alice through src/api (Z-1): rewrite the routes

So Bob asks Alice for it, instead of editing behind her back
$ bob msg send alice I need src/api/routes.rs for a 500 on POST, how long will you be?
sent M-1

Alice reads her mail
$ alice msg inbox
M-1  bob: I need src/api/routes.rs for a 500 on POST, how long will you be?

Alice answers, finishes, and lets go
$ alice msg send bob about 10 minutes, I will release src/api when the routes compile
sent M-2
$ alice zone release Z-1
released 1

Bob reads the answer
$ bob msg inbox
M-2  alice: about 10 minutes, I will release src/api when the routes compile

Alice can see her message arrived and was read
$ alice msg sent
M-2     to bob          read       about 10 minutes, I will release src/api when the routes compile

Now Bob gets the file
$ bob zone claim src/api/routes.rs --note fix the 500 on POST
Z-2  bob  src/api/routes.rs  30 min left  fix the 500 on POST

And the project knows who holds what
$ lockyard zone list
Z-2  bob  src/api/routes.rs  30 min left  fix the 500 on POST
```

## What to notice

**A claim is a tree, not a filename.** Alice claimed `src/api`; Bob was refused `src/api/routes.rs`
because it is inside it. Claiming the parent after a child is refused the same way.

**A refusal has an exit code.** `zone claim` and `zone check` exit `3` when someone else holds the
path, `4` when that could not be established in time, and `0` when the path is free. A wrapper
script can act on that without reading the message.

**A claim expires.** `30 min left` is a lease, not a lock: an agent that dies does not take the
folder with it. `lockyard zone renew` extends it while the work is still going on.

**Mail is for the thing blocking you.** Bob did not sit and poll; he said what he needed. Alice's
`msg sent` shows the message reached Bob and that he read it, so she knows the silence afterwards
means "fine", not "never saw it".

## What this example does not show

Queuing for a held path (`lockyard zone queue`) and asking its holder to hand it over
(`lockyard zone request` / `zone handover`) need a server: in a local project the two agents share
only a SQLite file, with nowhere to put a waiting line that both can watch. Run
`lockyard zone queue src/api` locally and it says so rather than pretending.
