# Bounded executor workers

Queued jobs are durable journal entries, not parked OS threads. The executor starts a short-lived coordinator only when work needs dispatch. It claims each eligible job as `starting` under the jobs mutex, persists that claim, then creates at most `max_concurrency` workers. Workers reuse their thread for the next eligible job. The registry counts a worker through output collection and provenance signing until its `JoinHandle` is finished, so an already-terminal result cannot silently release physical worker capacity while it is still finalizing.

One temporary coordinator reaps completed threads and closes the enqueue-versus-worker-exit race. It exits when no registered worker or eligible work remains. There is no permanently idle worker pool or strong-reference cycle keeping an empty executor/state lock alive. Unknown execution blocks new claims. Existing running authorized work is preserved.

The existing scheduler still applies priority aging, FIFO ties, submitter-incarnation/project running quotas and aggregate CPU/RAM reservations. A blocked quota can cause a worker to retire and a later eligible job to start another bounded worker; it does not create one waiting thread per queued job. For example, four concurrent jobs from one submitter require an explicit corresponding quota as well as `max_concurrency = 4`:

```toml
[executor.limits]
max_concurrency = 4
max_pending_jobs = 4096

[executor.scheduling.queue]
max_pending_per_submitter = 4096
max_pending_per_project = 4096
max_running_per_submitter = 4
max_running_per_project = 4
```

A failed durable claim, worker/coordinator spawn failure, worker panic or unrecoverable journal write fences further dispatch. `node status` exposes `executor_dispatch_failed`; capabilities advertise the node as unavailable for fresh placement. Existing IDs still reconcile. A worker panic preserves `interrupted_unknown` evidence rather than guessing that its container stopped. Operators inspect/reconcile and restart after fixing the cause; neither queue repair nor restart automatically reruns an unknown execution. Cancellation and workload launch are ordered under the job lock. A cancellation accepted before launch prevents the workload spawn, including when it arrives during setup; setup may already have accessed the configured profile or provider. A cancellation accepted after launch is a stop request for the running job. Queued cancellations never run. The durable starting claim is recovered as unknown after a crash, so an uncertain execution is never automatically replayed.

A controlled Linux test used 1,000 synthetic queued journals with four concurrent workers and matching submitter/project quotas. It invoked synthetic callbacks, zero containers and zero real jobs. The dedicated process measured 2 threads before/after enqueue and 7 during processing: 4 workers plus 1 temporary coordinator in addition to the 2 baseline test threads. Exactly 4 Linux worker TIDs processed all 1,000 callbacks; the coordinator exited and the last executor owner was released. RSS was 6,604 KiB baseline, 17,136 KiB after enqueue and 18,672 KiB during processing. These are absolute fixture measurements, not a production throughput/SLA or container resource-limit proof.

The fixture is run in a dedicated test process with `LOCKYARD_QUEUE_MEASURE_EXCLUSIVE=1` and the exact test `executor::regression_tests::thousand_queued_jobs_use_bounded_workers_through_finalization_and_release_every_owner`. Normal parallel suites assert worker identity/concurrency invariants without attributing unrelated tests' global thread/RSS changes to this queue.
