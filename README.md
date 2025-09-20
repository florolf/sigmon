# sigmon

*Note: This is still experimental software, rely on it at your own risk*

This is a small [sigsum](https://sigsum.org) monitor. It watches a log for signatures made with keys of interest and can execute hooks when a matching signature is detected to notify interested parties of that fact.

It verifies that tree heads follow the specified [policy](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md), subsequent tree heads are consistent and that all the leaves returned by the log are indeed included properly. Crucially, it keeps enough state to do this without requesting inclusion or consistency proofs in the common case.

## Usage

Install the package into a virtualenv using your favorite tool, e.g. using `pip install git+https://github.com/florolf/sigmon`. The main command is called `sigmon` and supplies the `init` and `poll` subcommands, described below.

sigmon uses a single directory to store all configuration and state related to a log. It looks like this:

```
.
├── hooks
│   └── match
│       └── ...
├── policy
├── log
│   └── 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6.json
└── watchlist
```

The only mandatory file is `policy`, which is the [sigsum policy](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md) that describes the parameters of the log itself. The `log` subdirectory is created by the `init` subcommand and managed by `sigmon` itself thereafter. `watchlist` lists the keys to watch the log for and `hooks` contains the hooks that will get executed for specific events like `match`.

To get started using the `barreleye` test log, create an empty directory (the name is arbitrary, but naming it after the log makes sense) and create a minimal policy file:

```
$ mkdir barreleye
$ cat > barreleye/policy <<EOF
log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye
quorum none
EOF
```

(sigmon supports witnesses and quorum rules, but since these still change occasionally this would complicate the upkeep of this README)

Then, you can initialize the monitor state using the `init` command:

```
$ sigmon init barreleye
```

By default, this will set things up such that sigmon will tail the log from wherever it stands at this point in time. To replay the log from a specific index onwards, you can additionally specify the index of the first leaf to fetch (using `0` for the beginning of time):

```
$ sigmon init barreleye 0
```

You can use `-f` to force reinitialization even if a log state file is already present.

Now, you can poll the log:

```
$ sigmon poll barreleye
```

This will only perform a single polling cycle, you can use the `-i` argument to poll repeatedly, for example once per minute:

```
$ sigmon poll -i 60 barreleye
```

As the configuration stands, this won't really do anything interesting other than check that the log is operating correctly. Supply the `-v` option to see the API calls that are being made (`sigmon -v poll barreleye`).

To actually watch for keys, they need to be added to the `watchlist` file. Keys can be specified using either the verbatim public key or using the keyhash (both hex-encoded). The former is generally more useful because sigmon will also be able to validate the leaf signatures (and warn about invalid ones), but the latter allows one to watch for arbitrary key activity even if one does not know the corresponding public key.

Add a key to the watchlist as follows (or use `key` for a plain key instead):

```
$ echo "keyhash c915d88e12fd0424aa55db620a7eaabffcad62de22e1981e9ad690a684cf55db" > barreleye/watchlist
```

This keyhash has some activity in the barreleye log, so when you roll the state back to the beginning (using `sigmon init -f barreleye 0`) and then execute a poll, you should see some matches appear.

Finally, entries in the watchlist can have attributes that are mainly passed to hooks directly. However, the special `alias` attribute is used to assign a human-readable name to a key:

```
$ echo "keyhash c915d88e12fd0424aa55db620a7eaabffcad62de22e1981e9ad690a684cf55db alias=interesting-key email_address=notification@example.com" > barreleye/watchlist
```

Now, `interesting-key` will be used in log statements instead of the hard to recognize hash. The `email_address` attribute could be used by a hook to decide who to notify about matches. Note that attributes cannot contain spaces.

## Hooks

sigmon will execute hook scripts in certain cases. Currently, the only supported hook types are `match` and `leaf_info`, described below. Hooks are executed by runnign all the executable files (or symlinks to such files) in `hooks/$HOOK_TYPE/` in lexicographic order. The working directory is the top level state directory (i.e. the one that contains the policy file, for example) and all information is passed in through environment variables.

See the `extra/hooks` directory for some example hooks. They take their configuration from a global config file in the state directory (`hook_cfg.sh`) or the watchlist, where the latter takes precedence.

### `match`

A match event is emitted any time an item from the watchlist appears in the log.

sigmon takes care not to lose any `match` events. I.e. it only updates its internal state after all relevant hooks have been executed. If it or the system crashes before that, hooks that were already called for a log entry might get called again (i.e. "at least once" delivery semantics). Note that sigmon intentionally does *not* have any retry logic for when the execution of a hook itself fails (i.e. it returns an exit code other than zero).

The environment variables provided to the hook are:

 - `LOG_ENDPOINT`: The log endpoint URL from the policy file
 - `LEAF_INDEX`: The numerical index of the leaf that matched
 - `LEAF_CHECKSUM`: The contents of the `checksum` field of the leaf (hex-encoded)
 - `LEAF_SIGNATURE`: The contents of the `signature` field of the leaf (hex-encoded)
 - `LEAF_INFO_x` for each `leaf_info` result, where `x` is the leaf information hook name. See below for more information.
 - `KEY_HASH`: The contents of the `key_hash` field of the leaf (hex-encoded)
 - `KEY_ATTR_x` for each attribute `x` specified in the watchlist

Additionally, if the `key` directive was used in the watch file, the following variables are present:
 - `KEY`: The pubkey itself (hex-encoded)
 - `LEAF_SIGNATURE_VALID`: `1` if the leaf signature is valid, `0` otherwise.

### `leaf_info`

Before a match event is emitted, `leaf_info` hooks are run that can fetch auxiliary information about the leaf in an application-specific manner. For example, a `leaf_info` hook could be used to retrieve the document that has been signed by a key if all such documents are published in a well-known place based on their checksums. A `match` hook can then include this document in the notification that it sends out.

Some considerations for implementing a leaf information hook:
 - It should validate whatever information it retrieves against the `LEAF_CHEKSUM` parameter, otherwise an attacker could possibly falsify it in-flight.
 - It should print whatever information it wishes to add to stdout. If it has nothing to add, it should produce no output.
 - It can use the `KEY_HASH` or some `KEY_ATTR_` field to determine if it should handle a given leaf.
