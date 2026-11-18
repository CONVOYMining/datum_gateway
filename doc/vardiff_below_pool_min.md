## General

A DATUM pool tells the Gateway a minimum share difficulty, and by default the Gateway raises
every miner to it. Some pools size that minimum to the Gateway's *total* share rate, so behind
a busy Gateway each miner is asked for a difficulty sized for the whole fleet rather than for
itself. A small miner then finds a share only every few minutes. For a miner rented from a
marketplace that matters: the marketplace measures delivered hashrate from accepted shares, so
its reading turns choppy, the rig's owner is warned that the pool's difficulty is too high, and
some marketplace proxies reconnect a pool that has gone a couple of minutes without accepting
a share.

`stratum.vardiff_below_pool_min` lets each miner keep a difficulty that suits it, without
changing what the pool receives:

```json
"stratum": {
	"vardiff_below_pool_min": true
}
```

It is off by default, and can also be switched on the Config page without a restart. Switched
on while miners are connected, it applies from each one's next job, and vardiff then walks each
miner's difficulty down from the pool minimum gradually, one halving per vardiff step. With it
off, miners are raised to the pool's minimum as before.

## What changes

For pooled work, a job served below the pool minimum has two difficulties:

| | Set from | Used for |
| --- | --- | --- |
| Served | the miner's own vardiff | `mining.set_difficulty`, the nbits hint in `mining.notify`, and the Gateway's local acceptance of the miner's shares |
| Committed | the pool minimum | the coinbase target byte, and so the work commitment and its ABW bits, which the pool checks a share against |

A job served at or above the pool minimum is committed at its served difficulty, exactly as
without the option.

Every share that meets the served target is accepted, so the miner's delivered hashrate is
measured accurately, and vardiff and the idle timeouts see its real share rate. Only shares
that also meet the committed target are sent to the pool.

## Why the pool's credit is unchanged

Whether a hash meets the committed target does not depend on which difficulty the miner was
asked for. The shares forwarded are exactly the ones a miner working at the committed
difficulty would have found, with the same expected credit and the same variance. Blocks are
among them while the committed difficulty is at or below the network's, as it is on mainnet,
where every block also meets the committed target. Nothing is withheld; the miner only reports
the easier shares in between, which the Gateway keeps to itself.

The pool sees no difference: each forwarded share carries the committed target, as before.

## Details

- Quickdiff. A quickdiff job is new work only because its committed target byte differs from
  the work the miner holds. When the commitment is held at the pool minimum and a quickdiff on
  the miner's current job would carry the same byte (it only raises the served difficulty, still
  below the minimum or exactly at it), the Gateway sends just the new `mining.set_difficulty` and
  leaves the miner on its current work, rather than resending identical work that the miner would
  redo and resubmit as duplicates. A quickdiff is sent as usual whenever its work would differ:
  a new target byte, a new job, or another coinbase, such as the full one after a new block's
  subsidy-only work.
- Shares kept local. A share between the two targets is accepted but not sent to the pool,
  except when the pool would take no share for its job at all: the job has no template, or,
  under anti-withholding, has no assignment or one that has already been disclosed. Such a share
  is refused, as it would be if it had been forwarded.
- Not pooled. Work that is not pooled (the pool is unreachable and the Gateway is mining solo)
  has no pool minimum, so the two difficulties are equal.

## Related fixes

These apply with the option off too:

- Vardiff measures the rate at the difficulty it now serves, and starts measuring afresh
  whenever it sends a new difficulty. A share from an older, easier job is still accepted, but
  is not counted toward the rate as if it were at the new difficulty.
- When a harder difficulty is now served than a share's job was sent at, the share is credited
  at the served difficulty if it meets it, and otherwise accepted without credit.
- A share marked as quickdiff (`Q`) is only accepted for the job its quickdiff notify was sent
  for. The check runs after the block check, so a block the Gateway can recognise in such a
  share is still submitted before the share is refused.
- A quickdiff for a job the miner has not been sent yet sends only the new difficulty: that job
  is on its way as a regular notify, and a quickdiff copy of it would be the same work twice.

## datum.capabilities

Tools that point miners at a Gateway can ask what it supports. This is not a Stratum standard
method, and it needs no subscribe or authorize:

```
{"id":1,"method":"datum.capabilities","params":[]}
```

```json
{"error":null,"id":1,"result":{
	"gateway":"v0.5.0-beta","algo":"blake2b",
	"features":{"vardiff_below_pool_min":true,"reject_tls_probe":true},
	"pooled":true,"pool_min_diff":1048576}}
```

A feature listed with `false` is supported but switched off. A Gateway without the method
answers `Method not found`, which means none of these features. `pool_min_diff` is the pool's
current minimum as DATUM's integer difficulty (`mining.set_difficulty` sends 65535/65536 of
it), or `0` when not mining pooled. The reply carries only the release string, not the exact
build, and nothing about the pool or the miners beyond that minimum. Send `"params":[]`: as with
any request, one without `params` closes the connection.

## TLS probes

A connection is closed at once when a read starts with a TLS handshake record (`0x16`) and no
partial line is pending, as at the start of a connection. Some pool checkers, MiningRigRentals'
among them, try encrypted stratum first; left waiting, they time out and report a working
plain-stratum pool as failing.
