## General

DATUM Gateway is designed with the assumption that pool usernames are generally Bitcoin addresses.
While it is *possible* to specify non-addresses in your miner, and pass those through to the pool, the default username in the Gateway itself (the `mining`.`pool_address` configuration option) must always be a valid Bitcoin address, and the Gateway will not fully start until it is set to one.

The rest of this document deals with Stratum usernames specifically, and how they are interpreted.

**Always test your full mining stack configuration.**
Misconfiguration of either the DATUM Gateway or your miners *can* result in lost work that is impossible to recover!

## Limitations

DATUM Gateway has a limit of 191 characters for Stratum usernames, including all special features specified by them.

Your miner likely has a lower limit.
For example,
Avalons truncate usernames at 63 characters;
Whatsminer has a buffer overflow (which may damage your miner) if you exceed 127;
and so on.

Some miners replace special characters (anything except alphanumeric, underscores, periods, and tildes) with hex codes (for example, `%` becomes `%25`), which can contribute toward reaching these limits and/or potentially confuse anything looking for them.

Note that Stratum usernames are *only* used for pooled mining.
When in non-pooled mode, they have no effect whatsoever, and only `mining`.`pool_address` is used to create blocks.

## Bitcoin address requirements (non-pooled mode)

This version of DATUM Gateway supports Base58 (aka Legacy), Bech32 (aka Segwit), and Bech32m (aka Taproot) addresses, for Bitcoin and Bitcoin testnet only.

It will not detect if you are using an address for the wrong network.

## Worker names

Immediately following the Bitcoin address, you may append a period (`.`) and an arbitrary worker name.
For compatibility, pools might also support an underscore (`_`) separator, but the DATUM Gateway codebase itself does not, and the period must be used to make use of Gateway features.

If the Stratum username *begins* with a period, it is interpreted as a worker name only, and appended to the Gateway's default username (`mining`.`pool_address`) before being sent to the pool.

## Passing usernames to the pool

There are three different ways to pass usernames to your pool.

By default, the Stratum username is always passed in full, as-is.
You can make this explicit by setting `datum`.`pool_pass_full_users` to `true` in the config file, or "Send Miner Usernames To Pool: Override Bitcoin Address" in the web configurator.

If you change `datum`.`pool_pass_full_users` to `false`, you can then set `datum`.`pool_pass_workers` instead (or "Send Miner Usernames To Pool: Send as worker names" in the web configurator).
With this setting, the entire Stratum username will be appended after the default username (`mining`.`pool_address`) as a worker.

Finally, if you set both options to `false`, the Stratum username will be ignored entirely.
Instead, only the configured default username (`mining`.`pool_address`) will be used, without any worker names.
