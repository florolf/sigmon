# Sigsum log mirroring

Distinct from its regular monitoring functionality, sigmon also contains a tool to mirror a Sigsum log into the [tlog-tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md) format in a single-shot or streaming fashion. This is particularly useful for archiving a Sigsum log that is being retired for posterity (see <https://github.com/geomys/ct-archive/> for a similar tool for CT logs).

The leaves generated are identical to the [original](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md?ref_type=heads#224--merkle-tree-leaf) Sigsum leaves.

Note that this is more of a demo than anything else. In particular, the tlog-tiles implementation included in here probably doesn't yet use the proper amount of barriers to make sure the on-disk state is always consistent when considering power loss events and such. It should be fine for one-shot mirroring of a given log though.

We automatically convert the log and witness keys from the policy to vkeys and informationally print them into the `vkeys.txt` file in the mirror directory. The log and witness signatures on a checkpoint get reformatted and attached to the tlog-tiles `checkpoint` file.

## Usage

You need to install the sigmon package first (e.g. in a virtualenv, see the top-level README).

Given a policy file, initialize the mirror tree:

```
$ python -m sigmon.mirror_cli init /path/to/mirror/dir policy
```

Where `policy` is a Sigsum policy file. If more than one log is defined in that policy, you can filter for the specific log you want like in `sigmon`:

```
$ python -m sigmon.mirror_cli init /path/to/mirror/dir policy --log barreleye
```

Then, again like with `sigmon`, run either a one-shot mirror update:

```
$ python -m sigmon.mirror_cli -v poll /path/to/mirror/dir
```

Or poll the log repeatedly, for example every 60 seconds:

```
$ python -m sigmon.mirror_cli -v poll /path/to/mirror/dir -i 60
```

The log endpoint and policy are persisted in `.sigmon` in the mirror directory so there is no need to specify them again.
