// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! FAT12, FAT16 and FAT32 (`fatgen103`), read-only.
//!
//! [`mount`] parses the boot sector ([`boot`]), loads the first FAT
//! ([`table`]) and answers the [`FileSystem`] calls. Directories are
//! walked by [`dir::Walker`] over a cluster [`chain::Chain`]; a file's
//! content is the chain of its clusters cut to its size.
//!
//! Node ids are the volume byte offset of the entry's short-name record.
//! The root of FAT12/16 is `NodeId(0)`. The root of FAT32 is the first byte
//! of the root cluster plus one: the design says the cluster's first byte,
//! but the first entry of the root directory sits exactly there, and an
//! entry offset is always a multiple of 32, so the odd offset cannot collide.
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use atlas_fs_core::fs::{DirBatch, DirProgress, FileSystem};
//! use atlas_fs_core::io::file::FileSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let source = Arc::new(FileSource::open(Path::new("volume.img"))?);
//! let volume = atlas_fat::mount(source)?;
//! println!("{}", volume.info().name);
//!
//! let mut stream = volume.read_dir(volume.root())?;
//! let mut batch = DirBatch::new();
//! while stream.next_batch(&mut batch, 256)? == DirProgress::More {}
//! for entry in batch.iter() {
//!     println!("{}", entry.name);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::sync::Arc;

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::fs::{
    AllocationMap, DirEntry, DirProgress, DirStream, EntryFlags, Extent, FileSystem,
    MAX_ALLOCATION_BUCKETS, Metadata, NodeId, NodeKind, Stream, VolumeInfo,
};
use atlas_fs_core::io::block::BlockSource;

use boot::{FatKind, Geometry};
use chain::{Chain, Limit, MAX_DIR_BYTES};
use dir::{ATTR_LONG_NAME, ATTR_VOLUME, ENTRY_LEN, ShortEntry, Walker};
use table::FatTable;

pub mod boot;
pub mod chain;
pub mod cp437;
pub mod dir;
// Seed inputs for the fuzz targets; `volumes()` is shared with Disk Atlas, which adds the probe heads.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod fuzz_seeds;
pub mod table;

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(dead_code, missing_docs)]
pub mod test_volume;

/// Bytes of the root directory read at mount to find the label entry.
const LABEL_SCAN: u64 = 16 * 1024;
/// Clusters read from the FAT at once for the allocation map.
const MAP_PIECE: u64 = 65_536;

/// A mounted FAT volume.
pub struct Fat {
    source: Arc<dyn BlockSource>,
    geo: Geometry,
    table: Arc<FatTable>,
    root: u64,
    info: VolumeInfo,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Fat>();
};

/// Mounts the FAT volume in `source`.
///
/// Fails when the boot sector is not a valid FAT boot sector or the source
/// ends inside the first FAT.
pub fn mount(source: Arc<dyn BlockSource>) -> Result<Fat> {
    let mut sector = [0u8; boot::BOOT_LEN];
    let have = usize::try_from(source.len()).map_or(sector.len(), |l| l.min(sector.len()));
    if let Some(dst) = sector.get_mut(..have) {
        source.read_at(0, dst)?;
    }
    let geo = boot::parse(sector.get(..have).unwrap_or(&[]))?;
    let table = Arc::new(FatTable::load(Arc::clone(&source), &geo)?);
    let root = if geo.kind == FatKind::Fat32 {
        let at = geo.cluster_offset(geo.root_cluster).ok_or_else(|| {
            Error::from(Corruption::new(
                "FAT boot sector",
                Location::Unspecified,
                CorruptKind::InvalidValue {
                    field: "root cluster",
                    value: u64::from(geo.root_cluster),
                },
            ))
        })?;
        at.saturating_add(1)
    } else {
        0
    };
    let mut fat = Fat {
        source,
        geo,
        table,
        root,
        info: VolumeInfo::new(""),
    };
    fat.info = fat.volume_info();
    Ok(fat)
}

fn not_found(node: u64) -> Error {
    Error::NotFound { node }
}

impl Fat {
    /// The geometry the boot sector gave.
    pub fn geometry(&self) -> &Geometry {
        &self.geo
    }

    fn volume_info(&self) -> VolumeInfo {
        let mut label = self.geo.label;
        // The label entry in the root directory wins over the boot sector's.
        if let Ok(root) = self.root_chain() {
            let len = root.len().min(LABEL_SCAN);
            if let Ok(len) = usize::try_from(len) {
                let mut data = vec![0u8; len];
                if root.read_at(0, &mut data).is_ok()
                    && let Some(found) = dir::find_label(&data)
                {
                    label = found;
                }
            }
        }
        let name: String = label.iter().map(|&b| cp437::decode(b)).collect();
        let name = name.trim_end().to_owned();
        let name = if name.is_empty() || name == "NO NAME" {
            "FAT volume".to_owned()
        } else {
            name
        };
        let mut info = VolumeInfo::new(name);
        info.format = Some(self.geo.kind.name());
        info.total_bytes = Some(self.geo.data_bytes());
        info.free_bytes = self
            .table
            .count_free()
            .map(|n| n.saturating_mul(u64::from(self.geo.cluster_size)));
        info.local_times = true;
        info
    }

    fn root_chain(&self) -> Result<Arc<Chain>> {
        if self.geo.kind == FatKind::Fat32 {
            self.follow_dir(self.geo.root_cluster)
        } else {
            Ok(Arc::new(Chain::region(
                Arc::clone(&self.source),
                self.geo.root_offset,
                self.geo.root_bytes,
            )))
        }
    }

    fn follow_dir(&self, first: u32) -> Result<Arc<Chain>> {
        if first < 2 {
            return Ok(Arc::new(Chain::empty(Arc::clone(&self.source))));
        }
        let max = MAX_DIR_BYTES
            .checked_div(u64::from(self.geo.cluster_size))
            .unwrap_or(0);
        Ok(Arc::new(Chain::follow(
            &self.geo,
            &self.table,
            Arc::clone(&self.source),
            first,
            Limit::Directory(max),
        )?))
    }

    /// The short entry at `node`, which must be a live file or folder entry.
    fn entry_at(&self, node: NodeId) -> Result<ShortEntry> {
        let off = node.0;
        let lowest = if self.geo.kind == FatKind::Fat32 {
            self.geo.data_offset
        } else {
            self.geo.root_offset
        };
        let in_range = match off.checked_add(ENTRY_LEN as u64) {
            Some(end) => end <= self.source.len(),
            None => false,
        };
        if !off.is_multiple_of(ENTRY_LEN as u64) || off < lowest || !in_range {
            return Err(not_found(off));
        }
        let mut buf = [0u8; ENTRY_LEN];
        self.source.read_at(off, &mut buf)?;
        let first = buf.first().copied().unwrap_or(0);
        let attr = buf.get(11).copied().unwrap_or(0);
        if first == 0 || first == 0xE5 || attr & 0x3F == ATTR_LONG_NAME || attr & ATTR_VOLUME != 0 {
            return Err(not_found(off));
        }
        ShortEntry::parse(&buf, self.geo.kind).ok_or_else(|| not_found(off))
    }

    /// The bytes of the folder `dir`.
    fn dir_chain(&self, dir: NodeId) -> Result<Arc<Chain>> {
        if dir.0 == self.root {
            return self.root_chain();
        }
        let entry = self.entry_at(dir)?;
        if !entry.is_dir() {
            return Err(Error::NotADirectory { node: dir.0 });
        }
        self.follow_dir(entry.first_cluster)
    }

    /// The clusters of a file, cut to its size.
    fn file_chain(&self, entry: &ShortEntry) -> Result<Chain> {
        let size = u64::from(entry.size);
        if size == 0 || entry.first_cluster < 2 {
            // A file with a size but no clusters reads as damaged at byte 0.
            let empty = Chain::empty(Arc::clone(&self.source));
            return Ok(if size == 0 {
                empty
            } else {
                empty.with_size(size)
            });
        }
        let clusters = size.div_ceil(u64::from(self.geo.cluster_size.max(1)));
        Ok(Chain::follow(
            &self.geo,
            &self.table,
            Arc::clone(&self.source),
            entry.first_cluster,
            Limit::Truncate(clusters),
        )?
        .with_size(size))
    }
}

struct FatDir {
    walker: Walker,
    done: bool,
}

impl DirStream for FatDir {
    fn next_batch(
        &mut self,
        out: &mut atlas_fs_core::fs::DirBatch,
        max: usize,
    ) -> Result<DirProgress> {
        if self.done {
            return Ok(DirProgress::Done);
        }
        let mut added = 0usize;
        // Bounded: each turn consumes one slot of a bounded chain.
        while added < max {
            match self.walker.next() {
                Ok(Some(found)) => {
                    let e = found.entry;
                    let dir = e.is_dir();
                    out.push(DirEntry {
                        node: NodeId(found.node),
                        name: &self.walker.name,
                        kind: if dir {
                            NodeKind::Directory
                        } else {
                            NodeKind::File
                        },
                        size: if dir { None } else { Some(u64::from(e.size)) },
                        resource_size: None,
                        modified: e.modified(),
                        flags: e.flags(),
                    });
                    added = added.saturating_add(1);
                }
                Ok(None) => {
                    self.done = true;
                    return Ok(DirProgress::Done);
                }
                Err(e) => {
                    self.done = true;
                    return Err(e);
                }
            }
        }
        Ok(DirProgress::More)
    }
}

impl FileSystem for Fat {
    fn info(&self) -> VolumeInfo {
        self.info.clone()
    }

    fn root(&self) -> NodeId {
        NodeId(self.root)
    }

    fn metadata(&self, node: NodeId) -> Result<Metadata> {
        let mut meta = Metadata {
            node,
            kind: NodeKind::Directory,
            size: None,
            resource_size: None,
            created: None,
            modified: None,
            accessed: None,
            flags: EntryFlags::EMPTY,
            link_target: None,
            finder_codes: None,
            owner: None,
            attributes: None,
            finder_info: None,
        };
        if node.0 == self.root {
            return Ok(meta);
        }
        let e = self.entry_at(node)?;
        if !e.is_dir() {
            meta.kind = NodeKind::File;
            meta.size = Some(u64::from(e.size));
        }
        meta.created = e.created();
        meta.modified = e.modified();
        meta.accessed = e.accessed();
        meta.flags = e.flags();
        Ok(meta)
    }

    fn lookup(&self, dir: NodeId, name: &str) -> Result<Option<NodeId>> {
        let want: String = name.chars().flat_map(char::to_lowercase).collect();
        let mut walker = Walker::new(self.dir_chain(dir)?, self.geo.kind);
        let mut lowered = String::new();
        while let Some(found) = walker.next()? {
            lowered.clear();
            lowered.extend(walker.name.chars().flat_map(char::to_lowercase));
            if lowered == want {
                return Ok(Some(NodeId(found.node)));
            }
        }
        Ok(None)
    }

    fn read_dir(&self, dir: NodeId) -> Result<Box<dyn DirStream>> {
        let chain = self.dir_chain(dir)?;
        Ok(Box::new(FatDir {
            walker: Walker::new(chain, self.geo.kind),
            done: false,
        }))
    }

    fn extents(&self, node: NodeId, stream: Stream) -> Result<Vec<Extent>> {
        if node.0 == self.root {
            return Err(Error::IsADirectory { node: node.0 });
        }
        let e = self.entry_at(node)?;
        if e.is_dir() {
            return Err(Error::IsADirectory { node: node.0 });
        }
        if stream == Stream::Resource {
            return Ok(Vec::new());
        }
        let chain = self.file_chain(&e)?;
        Ok(chain
            .runs()
            .iter()
            .map(|r| Extent {
                offset: r.disk,
                len: r.len,
            })
            .collect())
    }

    fn allocation_map(&self, buckets: usize) -> Result<AllocationMap> {
        let total = u64::from(self.geo.cluster_count);
        let n = buckets
            .clamp(1, MAX_ALLOCATION_BUCKETS)
            .min(usize::try_from(total).unwrap_or(usize::MAX))
            .max(1);
        let n64 = u64::try_from(n).unwrap_or(1);
        let mut density = Vec::with_capacity(n);
        let mut values = Vec::new();
        for i in 0..n64 {
            let lo = i.saturating_mul(total).checked_div(n64).unwrap_or(0);
            let hi = i
                .saturating_add(1)
                .saturating_mul(total)
                .checked_div(n64)
                .unwrap_or(0);
            let mut used = 0u64;
            let mut at = lo;
            while at < hi {
                let take = hi.saturating_sub(at).min(MAP_PIECE);
                values.clear();
                let first = u32::try_from(at.saturating_add(2)).unwrap_or(u32::MAX);
                let count = u32::try_from(take).unwrap_or(u32::MAX);
                self.table.values(first, count, &mut values)?;
                let n_used = values.iter().filter(|&&v| v != 0).count();
                used = used.saturating_add(u64::try_from(n_used).unwrap_or(0));
                at = at.saturating_add(take);
            }
            let blocks = hi.saturating_sub(lo).max(1);
            let d = used.saturating_mul(255).div_ceil(blocks);
            density.push(u8::try_from(d).unwrap_or(255));
        }
        Ok(AllocationMap::new(
            self.geo.data_offset,
            self.geo.data_bytes(),
            density,
        ))
    }

    fn open(&self, node: NodeId, stream: Stream) -> Result<Arc<dyn BlockSource>> {
        if node.0 == self.root {
            return Err(Error::IsADirectory { node: node.0 });
        }
        let e = self.entry_at(node)?;
        if e.is_dir() {
            return Err(Error::IsADirectory { node: node.0 });
        }
        if stream == Stream::Resource {
            return Err(Error::NoSuchStream { node: node.0 });
        }
        Ok(Arc::new(self.file_chain(&e)?))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::test_volume::{Built, standard};
    use super::*;
    use atlas_fs_core::fs::DirBatch;
    use atlas_fs_core::io::block::MemSource;

    const KINDS: [FatKind; 3] = [FatKind::Fat12, FatKind::Fat16, FatKind::Fat32];

    fn mounted(built: &Built) -> Fat {
        mount(Arc::new(MemSource::new(built.trimmed()))).expect("mount")
    }

    fn list(fs: &Fat, dir: NodeId) -> Vec<(String, NodeId, NodeKind, Option<u64>)> {
        let mut stream = fs.read_dir(dir).unwrap();
        let mut batch = DirBatch::default();
        let mut out = Vec::new();
        loop {
            batch.clear();
            let progress = stream.next_batch(&mut batch, 3).unwrap();
            out.extend(
                batch
                    .iter()
                    .map(|e| (e.name.to_owned(), e.node, e.kind, e.size)),
            );
            if progress == DirProgress::Done {
                return out;
            }
        }
    }

    fn read_all(source: &dyn BlockSource) -> Vec<u8> {
        let mut buf = vec![0u8; usize::try_from(source.len()).unwrap()];
        source.read_at(0, &mut buf).unwrap();
        buf
    }

    /// Every live item by path, through `read_dir`.
    fn walk(fs: &Fat, dir: NodeId, prefix: &str, out: &mut BTreeMap<String, (NodeId, NodeKind)>) {
        for (name, node, kind, _) in list(fs, dir) {
            let path = format!("{prefix}{name}");
            out.insert(path.clone(), (node, kind));
            if kind == NodeKind::Directory {
                walk(fs, node, &format!("{path}/"), out);
            }
        }
    }

    #[test]
    fn the_whole_tree_and_every_file_match_what_was_built() {
        for kind in KINDS {
            let built = standard(kind);
            let fs = mounted(&built);
            assert_eq!(fs.info().format, Some(kind.name()));
            assert_eq!(fs.info().name, "ATLAS");
            let mut seen = BTreeMap::new();
            walk(&fs, fs.root(), "/", &mut seen);
            let live: Vec<_> = built.items.iter().filter(|i| !i.deleted).collect();
            assert_eq!(seen.len(), live.len(), "{kind:?}: {seen:?}");
            for item in live {
                let (node, k) = seen
                    .get(&item.path)
                    .unwrap_or_else(|| panic!("{kind:?}: missing {}", item.path));
                assert_eq!(node.0, item.record, "{kind:?}: node of {}", item.path);
                if item.is_dir {
                    assert_eq!(*k, NodeKind::Directory);
                    continue;
                }
                let meta = fs.metadata(*node).unwrap();
                assert_eq!(meta.size, Some(item.data.len() as u64));
                let source = fs.open(*node, Stream::Data).unwrap();
                assert_eq!(read_all(&*source), item.data, "{kind:?}: {}", item.path);
            }
        }
    }

    #[test]
    fn hidden_flag_and_deleted_entries() {
        let built = standard(FatKind::Fat16);
        let fs = mounted(&built);
        let root = list(&fs, fs.root());
        assert!(root.iter().all(|(n, ..)| n != "Gone.txt"));
        let secret = root.iter().find(|(n, ..)| n == "secret.sys").unwrap();
        let meta = fs.metadata(secret.1).unwrap();
        assert!(meta.flags.contains(EntryFlags::HIDDEN));
    }

    #[test]
    fn lookup_ignores_case_and_finds_long_names() {
        for kind in KINDS {
            let built = standard(kind);
            let fs = mounted(&built);
            let frag = fs.lookup(fs.root(), "frag.bin").unwrap().unwrap();
            assert_eq!(frag.0, built.item("/FRAG.BIN").record);
            let docs = fs.lookup(fs.root(), "DOCS").unwrap().unwrap();
            let long = fs
                .lookup(docs, &test_volume::LONG_NAME.to_uppercase())
                .unwrap();
            assert!(long.is_some(), "{kind:?}");
            assert_eq!(fs.lookup(fs.root(), "nothing").unwrap(), None);
            assert!(matches!(
                fs.lookup(frag, "x"),
                Err(Error::NotADirectory { .. })
            ));
        }
    }

    #[test]
    fn extents_follow_the_fragments() {
        let built = standard(FatKind::Fat16);
        let fs = mounted(&built);
        let frag = fs.lookup(fs.root(), "FRAG.BIN").unwrap().unwrap();
        let extents = fs.extents(frag, Stream::Data).unwrap();
        let item = built.item("/FRAG.BIN");
        assert!(extents.len() > 1, "fragmented");
        let total: u64 = extents.iter().map(|e| e.len).sum();
        assert_eq!(total, item.clusters.len() as u64 * built.cluster_size);
        for (ext, cluster) in extents.iter().zip(&item.clusters) {
            assert_eq!(
                ext.offset,
                built.data_offset + u64::from(cluster - 2) * built.cluster_size
            );
        }
        assert!(fs.extents(frag, Stream::Resource).unwrap().is_empty());
        let docs = fs.lookup(fs.root(), "docs").unwrap().unwrap();
        assert!(matches!(
            fs.extents(docs, Stream::Data),
            Err(Error::IsADirectory { .. })
        ));
    }

    #[test]
    fn allocation_map_counts_the_used_clusters() {
        for kind in KINDS {
            let built = standard(kind);
            let fs = mounted(&built);
            let clusters = usize::try_from(built.cluster_count).unwrap();
            let total = clusters.min(MAX_ALLOCATION_BUCKETS);
            let map = fs.allocation_map(clusters).unwrap();
            assert_eq!(map.start, built.data_offset);
            assert_eq!(map.density.len(), total);
            assert!(map.density.iter().any(|&d| d > 0), "{kind:?}: some used");
            assert!(map.density.iter().any(|&d| d < 255), "{kind:?}: some free");
            let free = usize::try_from(fs.info().free_bytes.unwrap() / built.cluster_size).unwrap();
            assert!(free > 0 && free < clusters, "{kind:?}");
            if total == clusters {
                // One bucket per cluster: each is used (255) or free (0).
                assert!(map.density.iter().all(|&d| d == 0 || d == 255));
                let used = map.density.iter().filter(|&&d| d == 255).count();
                assert_eq!(free, clusters - used, "{kind:?}");
            }
            let coarse = fs.allocation_map(4).unwrap();
            assert_eq!(coarse.density.len(), 4);
            assert_eq!(fs.allocation_map(0).unwrap().density.len(), 1);
        }
    }

    #[test]
    fn a_folder_and_the_root_are_not_files() {
        for kind in [FatKind::Fat16, FatKind::Fat32] {
            let built = standard(kind);
            let fs = mounted(&built);
            let docs = fs.lookup(fs.root(), "docs").unwrap().unwrap();
            assert!(matches!(
                fs.open(docs, Stream::Data),
                Err(Error::IsADirectory { .. })
            ));
            assert!(matches!(
                fs.open(fs.root(), Stream::Data),
                Err(Error::IsADirectory { .. })
            ));
            let file = fs.lookup(docs, "notes.txt").unwrap().unwrap();
            assert!(matches!(
                fs.open(file, Stream::Resource),
                Err(Error::NoSuchStream { .. })
            ));
            assert_eq!(fs.metadata(fs.root()).unwrap().kind, NodeKind::Directory);
        }
    }

    #[test]
    fn invented_node_ids_are_not_found() {
        let built = standard(FatKind::Fat32);
        let fs = mounted(&built);
        let first = list(&fs, fs.root())[0].1;
        let bogus = [
            1,
            3,
            31,
            first.0 + 1,
            first.0 + 5,
            built.fat_offset,
            built.data_offset - 32,
            u64::MAX,
            u64::MAX - 31,
            built.image.len() as u64 + 64,
        ];
        for node in bogus {
            if node == fs.root().0 {
                continue;
            }
            assert!(
                fs.metadata(NodeId(node)).is_err(),
                "node {node} must not resolve"
            );
            assert!(fs.read_dir(NodeId(node)).is_err());
            assert!(fs.open(NodeId(node), Stream::Data).is_err());
        }
    }

    #[test]
    fn the_fat32_root_does_not_collide_with_its_first_entry() {
        let built = standard(FatKind::Fat32);
        let fs = mounted(&built);
        for (_, node, ..) in list(&fs, fs.root()) {
            assert_ne!(node, fs.root());
        }
    }

    #[test]
    fn mounting_rejects_garbage_and_truncation() {
        for bytes in [vec![], vec![0u8; 100], vec![0u8; 4096], vec![0xFFu8; 4096]] {
            assert!(mount(Arc::new(MemSource::new(bytes))).is_err());
        }
        let built = standard(FatKind::Fat16);
        let cut = usize::try_from(built.fat_offset).unwrap() + 100;
        let short = built.image[..cut].to_vec();
        assert!(mount(Arc::new(MemSource::new(short))).is_err());
    }

    #[test]
    fn a_cut_image_still_lists_and_fails_at_the_damage() {
        let built = standard(FatKind::Fat16);
        let fs = mount(Arc::new(MemSource::new(
            built.image[..usize::try_from(built.data_offset).unwrap() + 700].to_vec(),
        )))
        .unwrap();
        // The root directory is before the cut, so it lists; the file far
        // into the data area is out of range at read time, not at open.
        let frag = fs.lookup(fs.root(), "FRAG.BIN").unwrap().unwrap();
        let source = fs.open(frag, Stream::Data).unwrap();
        let mut buf = vec![0u8; usize::try_from(source.len()).unwrap()];
        assert!(source.read_at(0, &mut buf).is_err());
    }

    #[test]
    fn a_damaged_chain_reads_up_to_the_damage() {
        let mut built = standard(FatKind::Fat16);
        let item = built.item("/FRAG.BIN").clone();
        // Point the second cluster at a free entry's neighbour: value 0.
        let second = item.clusters[1];
        let at = built.fat_entry_at(item.clusters[0]);
        let _ = second;
        built.image[at] = 0;
        built.image[at + 1] = 0;
        let fs = mounted(&built);
        let node = fs.lookup(fs.root(), "FRAG.BIN").unwrap().unwrap();
        let source = fs.open(node, Stream::Data).unwrap();
        let cs = usize::try_from(built.cluster_size).unwrap();
        let mut first = vec![0u8; cs];
        source.read_at(0, &mut first).unwrap();
        assert_eq!(first, item.data[..cs]);
        let mut all = vec![0u8; usize::try_from(source.len()).unwrap()];
        assert!(source.read_at(0, &mut all).is_err());
    }
}
