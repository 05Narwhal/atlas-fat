# atlas-fat

A read-only FAT12, FAT16 and FAT32 reader. It implements `atlas_fs_core::fs::FileSystem`, so a mounted volume
lists folders, looks up names, reads file content and reports its allocation through the same trait as the
other `atlas-*` readers.

- Boot sector and BPB checks for all three FAT types, FAT32 root cluster chains.
- Short (8.3, OEM code page 437) and long (UTF-16) names, with the case flags Windows NT writes.
- Cluster chains read through a bounded, loop-checked walker; a damaged FAT is an error, not a hang.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

The cluster-chain walker (`chain`) is public because the exFAT, ISO 9660 and UDF readers build on it.

```rust,no_run
use std::sync::Arc;
use atlas_fs_core::fs::FileSystem;
use atlas_fs_core::io::block::BlockSource;
use atlas_fs_core::io::file::FileSource;

let source: Arc<dyn BlockSource> = Arc::new(FileSource::open("volume.img".as_ref())?);
let volume = atlas_fat::mount(source)?;
let mut dir = volume.read_dir(volume.root())?;
# Ok::<(), atlas_fs_core::error::Error>(())
```

The `test-util` feature exposes the test volume builder and fuzz seed inputs; it is for tests of crates that use
this one and is not part of the stable API.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
