# demo-payments-desk

[Crypto Migration Desk](https://github.com/Dakshhhhh-ops/fliptheswitch)'s live run 3 on [Switch](https://github.com/sandbox-quantum/switch),
replayed onto GitHub as pull requests. The agents' commits, signed approvals
and signed ships are the originals from the run's git
([origin.bundle](https://github.com/Dakshhhhh-ops/fliptheswitch/blob/main/docs/live-run-3/origin.bundle), [chat log](https://github.com/Dakshhhhh-ops/fliptheswitch/blob/main/docs/live-run-3/chat-log.md)).

- **main** is the run's main: the planted payments app, then one `Ship F<n>`
  merge per shipped finding, each signed by the shipper's ML-DSA-65 key.
- **Pull requests**, one per finding branch. A PR's head needs the reviewer's
  signed approval: the annotated tag `approved/<sha>`.
- **desk-gate** (this branch, the default one) is the desk's git gate as a
  GitHub Actions check. It posts `desk-gate/approval` on every PR and
  `desk-gate/main` on every commit of main. F6's PR shows ✗: the run ended
  before the reviewer approved it.

github.com has no pre-receive hooks (only GitHub Enterprise Server does), so
here a bad commit is reported, not refused. A ruleset blocks deleting or
force-pushing main. The desk's own origin still refuses a bad push outright.
This branch holds the gate's code and public keys only, so main stays exactly
what the agents signed.
