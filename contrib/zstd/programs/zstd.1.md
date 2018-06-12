zstd(1) -- zstd, zstdmt, unzstd, zstdcat - Compress or decompress .zst files
============================================================================

SYNOPSIS
--------

`zstd` [*OPTIONS*] [-|_INPUT-FILE_] [-o _OUTPUT-FILE_]

`zstdmt` is equivalent to `zstd -T0`

`unzstd` is equivalent to `zstd -d`

`zstdcat` is equivalent to `zstd -dcf`


DESCRIPTION
-----------
`zstd` is a fast lossless compression algorithm and data compression tool,
with command line syntax similar to `gzip (1)` and `xz (1)`.
It is based on the **LZ77** family, with further FSE & huff0 entropy stages.
`zstd` offers highly configurable compression speed,
with fast modes at > 200 MB/s per code,
and strong modes nearing lzma compression ratios.
It also features a very fast decoder, with speeds > 500 MB/s per core.

`zstd` command line syntax is generally similar to gzip,
but features the following differences :

  - Source files are preserved by default.
    It's possible to remove them automatically by using the `--rm` command.
  - When compressing a single file, `zstd` displays progress notifications
    and result summary by default.
    Use `-q` to turn them off.
  - `zstd` does not accept input from console,
    but it properly accepts `stdin` when it's not the console.
  - `zstd` displays a short help page when command line is an error.
    Use `-q` to turn it off.

`zstd` compresses or decompresses each _file_ according to the selected
operation mode.
If no _files_ are given or _file_ is `-`, `zstd` reads from standard input
and writes the processed data to standard output.
`zstd` will refuse to write compressed data to standard output
if it is a terminal : it will display an error message and skip the _file_.
Similarly, `zstd` will refuse to read compressed data from standard input
if it is a terminal.

Unless `--stdout` or `-o` is specified, _files_ are written to a new file
whose name is derived from the source _file_ name:

* When compressing, the suffix `.zst` is appended to the source filename to
  get the target filename.
* When decompressing, the `.zst` suffix is removed from the source filename to
  get the target filename

### Concatenation with .zst files
It is possible to concatenate `.zst` files as is.
`zstd` will decompress such files as if they were a single `.zst` file.

OPTIONS
-------

### Integer suffixes and special values
In most places where an integer argument is expected,
an optional suffix is supported to easily indicate large integers.
There must be no space between the integer and the suffix.

* `KiB`:
    Multiply the integer by 1,024 (2\^10).
    `Ki`, `K`, and `KB` are accepted as synonyms for `KiB`.
* `MiB`:
    Multiply the integer by 1,048,576 (2\^20).
    `Mi`, `M`, and `MB` are accepted as synonyms for `MiB`.

### Operation mode
If multiple operation mode options are given,
the last one takes effect.

* `-z`, `--compress`:
    Compress.
    This is the default operation mode when no operation mode option is specified
    and no other operation mode is implied from the command name
    (for example, `unzstd` implies `--decompress`).
* `-d`, `--decompress`, `--uncompress`:
    Decompress.
* `-t`, `--test`:
    Test the integrity of compressed _files_.
    This option is equivalent to `--decompress --stdout` except that the
    decompressed data is discarded instead of being written to standard output.
    No files are created or removed.
* `-b#`:
    Benchmark file(s) using compression level #
* `--train FILEs`:
    Use FILEs as a training set to create a dictionary.
    The training set should contain a lot of small files (> 100).
* `-l`, `--list`:
    Display information related to a zstd compressed file, such as size, ratio, and checksum.
    Some of these fields may not be available.
    This command can be augmented with the `-v` modifier.

### Operation modifiers

* `-#`:
    `#` compression level \[1-19] (default: 3)
* `--ultra`:
    unlocks high compression levels 20+ (maximum 22), using a lot more memory.
    Note that decompression will also require more memory when using these levels.
* `-T#`, `--threads=#`:
    Compress using `#` threads (default: 1).
    If `#` is 0, attempt to detect and use the number of physical CPU cores.
    In all cases, the nb of threads is capped to ZSTDMT_NBTHREADS_MAX==256.
    This modifier does nothing if `zstd` is compiled without multithread support.
* `-D file`:
    use `file` as Dictionary to compress or decompress FILE(s)
* `--nodictID`:
    do not store dictionary ID within frame header (dictionary compression).
    The decoder will have to rely on implicit knowledge about which dictionary to use,
    it won't be able to check if it's correct.
* `-o file`:
    save result into `file` (only possible with a single _INPUT-FILE_)
* `-f`, `--force`:
    overwrite output without prompting, and (de)compress symbolic links
* `-c`, `--stdout`:
    force write to standard output, even if it is the console
* `--[no-]sparse`:
    enable / disable sparse FS support,
    to make files with many zeroes smaller on disk.
    Creating sparse files may save disk space and speed up decompression by
    reducing the amount of disk I/O.
    default : enabled when output is into a file,
    and disabled when output is stdout.
    This setting overrides default and can force sparse mode over stdout.
* `--rm`:
    remove source file(s) after successful compression or decompression
* `-k`, `--keep`:
    keep source file(s) after successful compression or decompression.
    This is the default behavior.
* `-r`:
    operate recursively on dictionaries
* `-h`/`-H`, `--help`:
    display help/long help and exit
* `-V`, `--version`:
    display version number and exit.
    Advanced : `-vV` also displays supported formats.
    `-vvV` also displays POSIX support.
* `-v`:
    verbose mode
* `-q`, `--quiet`:
    suppress warnings, interactivity, and notifications.
    specify twice to suppress errors too.
* `-C`, `--[no-]check`:
    add integrity check computed from uncompressed data (default : enabled)
* `--`:
    All arguments after `--` are treated as files


DICTIONARY BUILDER
------------------
`zstd` offers _dictionary_ compression,
useful for very small files and messages.
It's possible to train `zstd` with some samples,
the result of which is saved into a file called a `dictionary`.
Then during compression and decompression, reference the same dictionary.
It will improve compression ratio of small files.
Typical gains range from 10% (at 64KB) to x5 better (at <1KB).

* `--train FILEs`:
    Use FILEs as training set to create a dictionary.
    The training set should contain a lot of small files (> 100),
    and weight typically 100x the target dictionary size
    (for example, 10 MB for a 100 KB dictionary).

    Supports multithreading if `zstd` is compiled with threading support.
    Additional parameters can be specified with `--train-cover`.
    The legacy dictionary builder can be accessed with `--train-legacy`.
    Equivalent to `--train-cover=d=8,steps=4`.
* `-o file`:
    Dictionary saved into `file` (default name: dictionary).
* `--maxdict=#`:
    Limit dictionary to specified size (default: 112640).
* `--dictID=#`:
    A dictionary ID is a locally unique ID that a decoder can use to verify it is
    using the right dictionary.
    By default, zstd will create a 4-bytes random number ID.
    It's possible to give a precise number instead.
    Short numbers have an advantage : an ID < 256 will only need 1 byte in the
    compressed frame header, and an ID < 65536 will only need 2 bytes.
    This compares favorably to 4 bytes default.
    However, it's up to the dictionary manager to not assign twice the same ID to
    2 different dictionaries.
* `--train-cover[=k#,d=#,steps=#]`:
    Select parameters for the default dictionary builder algorithm named cover.
    If _d_ is not specified, then it tries _d_ = 6 and _d_ = 8.
    If _k_ is not specified, then it tries _steps_ values in the range [50, 2000].
    If _steps_ is not specified, then the default value of 40 is used.
    Requires that _d_ <= _k_.

    Selects segments of size _k_ with highest score to put in the dictionary.
    The score of a segment is computed by the sum of the frequencies of all the
    subsegments of size _d_.
    Generally _d_ should be in the range [6, 8], occasionally up to 16, but the
    algorithm will run faster with d <= _8_.
    Good values for _k_ vary widely based on the input data, but a safe range is
    [2 * _d_, 2000].
    Supports multithreading if `zstd` is compiled with threading support.

    Examples:

    `zstd --train-cover FILEs`

    `zstd --train-cover=k=50,d=8 FILEs`

    `zstd --train-cover=d=8,steps=500 FILEs`

    `zstd --train-cover=k=50 FILEs`

* `--train-legacy[=selectivity=#]`:
    Use legacy dictionary builder algorithm with the given dictionary
    _selectivity_ (default: 9).
    The smaller the _selectivity_ value, the denser the dictionary,
    improving its efficiency but reducing its possible maximum size.
    `--train-legacy=s=#` is also accepted.

    Examples:

    `zstd --train-legacy FILEs`

    `zstd --train-legacy=selectivity=8 FILEs`


BENCHMARK
---------

* `-b#`:
    benchmark file(s) using compression level #
* `-e#`:
    benchmark file(s) using multiple compression levels, from `-b#` to `-e#` (inclusive)
* `-i#`:
    minimum evaluation time, in seconds (default : 3s), benchmark mode only
* `-B#`, `--block-size=#`:
    cut file(s) into independent blocks of size # (default: no block)
* `--priority=rt`:
    set process priority to real-time


ADVANCED COMPRESSION OPTIONS
----------------------------
### --zstd[=options]:
`zstd` provides 22 predefined compression levels.
The selected or default predefined compression level can be changed with
advanced compression options.
The _options_ are provided as a comma-separated list.
You may specify only the options you want to change and the rest will be
taken from the selected or default compression level.
The list of available _options_:

- `strategy`=_strat_, `strat`=_strat_:
    Specify a strategy used by a match finder.

    There are 8 strategies numbered from 1 to 8, from faster to stronger:
    1=ZSTD\_fast, 2=ZSTD\_dfast, 3=ZSTD\_greedy, 4=ZSTD\_lazy,
    5=ZSTD\_lazy2, 6=ZSTD\_btlazy2, 7=ZSTD\_btopt, 8=ZSTD\_btultra.

- `windowLog`=_wlog_, `wlog`=_wlog_:
    Specify the maximum number of bits for a match distance.

    The higher number of increases the chance to find a match which usually
    improves compression ratio.
    It also increases memory requirements for the compressor and decompressor.
    The minimum _wlog_ is 10 (1 KiB) and the maximum is 27 (128 MiB).

- `hashLog`=_hlog_, `hlog`=_hlog_:
    Specify the maximum number of bits for a hash table.

    Bigger hash tables cause less collisions which usually makes compression
    faster, but requires more memory during compression.

    The minimum _hlog_ is 6 (64 B) and the maximum is 26 (128 MiB).

- `chainLog`=_clog_, `clog`=_clog_:
    Specify the maximum number of bits for a hash chain or a binary tree.

    Higher numbers of bits increases the chance to find a match which usually
    improves compression ratio.
    It also slows down compression speed and increases memory requirements for
    compression.
    This option is ignored for the ZSTD_fast strategy.

    The minimum _clog_ is 6 (64 B) and the maximum is 28 (256 MiB).

- `searchLog`=_slog_, `slog`=_slog_:
    Specify the maximum number of searches in a hash chain or a binary tree
    using logarithmic scale.

    More searches increases the chance to find a match which usually increases
    compression ratio but decreases compression speed.

    The minimum _slog_ is 1 and the maximum is 26.

- `searchLength`=_slen_, `slen`=_slen_:
    Specify the minimum searched length of a match in a hash table.

    Larger search lengths usually decrease compression ratio but improve
    decompression speed.

    The minimum _slen_ is 3 and the maximum is 7.

- `targetLen`=_tlen_, `tlen`=_tlen_:
    Specify the minimum match length that causes a match finder to stop
    searching for better matches.

    A larger minimum match length usually improves compression ratio but
    decreases compression speed.
    This option is only used with strategies ZSTD_btopt and ZSTD_btultra.

    The minimum _tlen_ is 4 and the maximum is 999.

- `overlapLog`=_ovlog_,  `ovlog`=_ovlog_:
    Determine `overlapSize`, amount of data reloaded from previous job.
    This parameter is only available when multithreading is enabled.
    Reloading more data improves compression ratio, but decreases speed.

    The minimum _ovlog_ is 0, and the maximum is 9.
    0 means "no overlap", hence completely independent jobs.
    9 means "full overlap", meaning up to `windowSize` is reloaded from previous job.
    Reducing _ovlog_ by 1 reduces the amount of reload by a factor 2.
    Default _ovlog_ is 6, which means "reload `windowSize / 8`".
    Exception : the maximum compression level (22) has a default _ovlog_ of 9.

### -B#:
Select the size of each compression job.
This parameter is available only when multi-threading is enabled.
Default value is `4 * windowSize`, which means it varies depending on compression level.
`-B#` makes it possible to select a custom value.
Note that job size must respect a minimum value which is enforced transparently.
This minimum is either 1 MB, or `overlapSize`, whichever is largest.

### Example
The following parameters sets advanced compression options to those of
predefined level 19 for files bigger than 256 KB:

`--zstd`=windowLog=23,chainLog=23,hashLog=22,searchLog=6,searchLength=3,targetLength=48,strategy=6

BUGS
----
Report bugs at: https://github.com/facebook/zstd/issues

AUTHOR
------
Yann Collet
