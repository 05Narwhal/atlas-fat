// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Builds small FAT12, FAT16 and FAT32 volumes in memory, for tests and
//! fuzz seeds. Test code only: it panics on bad input.

use super::boot::FatKind;
use super::dir::short_checksum;

/// Date word of every entry: 2024-03-05.
pub const DATE: u16 = ((2024 - 1980) << 9) | (3 << 5) | 5;
/// Time word of every entry: 13:14:16.
pub const TIME: u16 = (13 << 11) | (14 << 5) | 8;
/// [`DATE`] and [`TIME`] as seconds since the Unix epoch.
pub const UNIX_SECONDS: i64 = 1_709_644_456;

/// What a file or folder is made like.
#[derive(Debug, Clone, Copy, Default)]
pub struct Opts {
    /// Spread the clusters out and put them in descending order.
    pub fragmented: bool,
    /// Hidden attribute.
    pub hidden: bool,
    /// System attribute.
    pub system: bool,
    /// Read-only attribute.
    pub read_only: bool,
    /// Written as a deleted entry (first byte `0xE5`); no clusters are used.
    pub deleted: bool,
}

struct EntryModel {
    name: String,
    long: bool,
    short: [u8; 11],
    nt_case: u8,
    attr: u8,
    /// Index of the directory this entry is, when it is one.
    dir: Option<usize>,
    data: Vec<u8>,
    deleted: bool,
    fragmented: bool,
}

struct DirModel {
    entries: Vec<EntryModel>,
    path: String,
}

/// One entry of a built volume.
#[derive(Debug, Clone)]
pub struct Item {
    /// Path from the root, as a listing reports the names.
    pub path: String,
    /// True for a folder.
    pub is_dir: bool,
    /// Content of a file.
    pub data: Vec<u8>,
    /// Written as deleted.
    pub deleted: bool,
    /// Hidden or system.
    pub hidden: bool,
    /// Byte offset of the short entry in the image (its node id).
    pub record: u64,
    /// The chain, in order.
    pub clusters: Vec<u32>,
}

/// A built volume.
pub struct Built {
    /// The whole image.
    pub image: Vec<u8>,
    /// The type built.
    pub kind: FatKind,
    /// Bytes per cluster.
    pub cluster_size: u64,
    /// Byte offset of cluster 2.
    pub data_offset: u64,
    /// Byte offset of the first FAT.
    pub fat_offset: u64,
    /// Byte offset of the fixed root directory (FAT12/16).
    pub root_offset: u64,
    /// Clusters in the data area.
    pub cluster_count: u32,
    /// The entries, in the order they were added (deleted ones too).
    pub items: Vec<Item>,
    /// Bytes up to the end of the last cluster in use.
    pub used_end: u64,
}

impl Built {
    /// The item at `path`.
    pub fn item(&self, path: &str) -> &Item {
        self.items
            .iter()
            .find(|i| i.path == path)
            .unwrap_or_else(|| panic!("no item {path}"))
    }

    /// The image without its trailing unused clusters.
    pub fn trimmed(&self) -> Vec<u8> {
        let end = usize::try_from(self.used_end).unwrap();
        self.image[..end.min(self.image.len())].to_vec()
    }

    /// Byte offset of the FAT entry of cluster `n` (FAT16 and FAT32 only).
    pub fn fat_entry_at(&self, n: u32) -> usize {
        let width = if self.kind == FatKind::Fat32 { 4 } else { 2 };
        usize::try_from(self.fat_offset).unwrap() + n as usize * width
    }
}

/// Builds a volume. Directory 0 is the root.
pub struct VolumeBuilder {
    kind: FatKind,
    bps: u32,
    spc: u32,
    clusters: u32,
    label: Option<String>,
    dirs: Vec<DirModel>,
}

/// `len` bytes of a pattern that differs between files and positions.
pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

fn is_short_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$')
}

/// `Some((short bytes, case bits))` when `name` is an 8.3 name a short entry
/// holds exactly: one case per part.
fn as_short(name: &str) -> Option<([u8; 11], u8)> {
    let (base, ext) = match name.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || name.matches('.').count() > 1 {
        return None;
    }
    if !base.chars().chain(ext.chars()).all(is_short_char) {
        return None;
    }
    let case_of = |s: &str| {
        let lower = s.chars().any(|c| c.is_ascii_lowercase());
        let upper = s.chars().any(|c| c.is_ascii_uppercase());
        (!(lower && upper)).then_some(lower)
    };
    let base_lower = case_of(base)?;
    let ext_lower = case_of(ext)?;
    let mut raw = [b' '; 11];
    for (i, b) in base.bytes().enumerate() {
        raw[i] = b.to_ascii_uppercase();
    }
    for (i, b) in ext.bytes().enumerate() {
        raw[8 + i] = b.to_ascii_uppercase();
    }
    let nt = (u8::from(base_lower) << 3) | (u8::from(ext_lower) << 4);
    Some((raw, nt))
}

impl VolumeBuilder {
    /// A volume of `kind` with the default geometry.
    pub fn new(kind: FatKind) -> Self {
        let (spc, clusters) = match kind {
            FatKind::Fat12 => (2, 300),
            FatKind::Fat16 => (1, 4100),
            FatKind::Fat32 => (1, 65_600),
        };
        Self {
            kind,
            bps: 512,
            spc,
            clusters,
            label: None,
            dirs: vec![DirModel {
                entries: Vec::new(),
                path: String::new(),
            }],
        }
    }

    /// Bytes per sector.
    pub fn bytes_per_sector(&mut self, bps: u32) -> &mut Self {
        self.bps = bps;
        self
    }

    /// Sectors per cluster.
    pub fn sectors_per_cluster(&mut self, spc: u32) -> &mut Self {
        self.spc = spc;
        self
    }

    /// The volume label entry in the root directory.
    pub fn label(&mut self, label: &str) -> &mut Self {
        self.label = Some(label.to_owned());
        self
    }

    fn entry(&mut self, parent: usize, name: &str, attr: u8, opts: Opts) -> EntryModel {
        let (short, nt_case, long) = match as_short(name) {
            Some((s, nt)) => (s, nt, false),
            None => {
                // An alias: up to 6 characters, ~N, the first 3 of the extension.
                let clean = |s: &str, n: usize| -> String {
                    s.chars()
                        .map(|c| {
                            if is_short_char(c) {
                                c.to_ascii_uppercase()
                            } else {
                                '_'
                            }
                        })
                        .take(n)
                        .collect()
                };
                let (base, ext) = name.rsplit_once('.').unwrap_or((name, ""));
                let n = self.dirs[parent].entries.len() + 1;
                let alias = format!("{}~{n}", clean(base, 6));
                let mut raw = [b' '; 11];
                for (i, b) in alias.bytes().take(8).enumerate() {
                    raw[i] = b;
                }
                for (i, b) in clean(ext, 3).bytes().enumerate() {
                    raw[8 + i] = b;
                }
                (raw, 0, true)
            }
        };
        let mut attr = attr;
        if opts.hidden {
            attr |= 0x02;
        }
        if opts.system {
            attr |= 0x04;
        }
        if opts.read_only {
            attr |= 0x01;
        }
        EntryModel {
            name: name.to_owned(),
            long,
            short,
            nt_case,
            attr,
            dir: None,
            data: Vec::new(),
            deleted: opts.deleted,
            fragmented: opts.fragmented,
        }
    }

    /// Adds a folder to directory `parent`; returns its index.
    pub fn dir(&mut self, parent: usize, name: &str) -> usize {
        self.dir_with(parent, name, Opts::default())
    }

    /// [`Self::dir`] with options.
    pub fn dir_with(&mut self, parent: usize, name: &str, opts: Opts) -> usize {
        let mut e = self.entry(parent, name, 0x10, opts);
        let index = self.dirs.len();
        e.dir = Some(index);
        let path = format!("{}/{name}", self.dirs[parent].path);
        self.dirs.push(DirModel {
            entries: Vec::new(),
            path,
        });
        self.dirs[parent].entries.push(e);
        index
    }

    /// Adds a file to directory `parent`.
    pub fn file(&mut self, parent: usize, name: &str, data: &[u8]) -> &mut Self {
        self.file_with(parent, name, data, Opts::default())
    }

    /// [`Self::file`] with options.
    pub fn file_with(&mut self, parent: usize, name: &str, data: &[u8], opts: Opts) -> &mut Self {
        let mut e = self.entry(parent, name, 0x20, opts);
        e.data = data.to_vec();
        self.dirs[parent].entries.push(e);
        self
    }

    /// Builds the image.
    pub fn build(&self) -> Built {
        let kind = self.kind;
        let bps = self.bps as usize;
        let cs = bps * self.spc as usize;
        let cc = self.clusters as usize;
        let root_entries = if kind == FatKind::Fat32 { 0 } else { 128usize };
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let reserved = if kind == FatKind::Fat32 { 32usize } else { 1 };
        let fats = 2usize;
        let table_bytes = match kind {
            FatKind::Fat12 => ((cc + 2) * 3).div_ceil(2),
            FatKind::Fat16 => (cc + 2) * 2,
            FatKind::Fat32 => (cc + 2) * 4,
        };
        let fat_sectors = table_bytes.div_ceil(bps);
        let total_sectors = reserved + fats * fat_sectors + root_sectors + cc * self.spc as usize;
        let fat_offset = reserved * bps;
        let root_offset = fat_offset + fats * fat_sectors * bps;
        let data_offset = root_offset + root_sectors * bps;
        let mut image = vec![0u8; total_sectors * bps];

        // Directory slot counts, then the clusters of everything.
        let slots_of = |d: usize| -> usize {
            let mut slots = if d == 0 { 0 } else { 2 };
            for e in &self.dirs[d].entries {
                slots += 1;
                if e.long {
                    slots += (e.name.encode_utf16().count() + 1).div_ceil(13).max(1);
                    // A name of an exact multiple of 13 units has no terminator.
                    if e.name.encode_utf16().count() % 13 == 0 {
                        slots -= 0;
                    }
                }
            }
            if d == 0 && self.label.is_some() {
                slots += 1;
            }
            slots + 1
        };
        let mut fat = vec![0u32; cc + 2];
        let mut next = 2usize;
        let mut alloc = |n: usize, fragmented: bool| -> Vec<u32> {
            let mut list = Vec::new();
            for k in 0..n {
                let c = if fragmented { next + k * 2 } else { next + k };
                assert!(c < cc + 2, "volume too small");
                list.push(c as u32);
            }
            next = list.last().map_or(next, |&c| c as usize + 1);
            if fragmented {
                list.reverse();
            }
            for w in list.windows(2) {
                fat[w[0] as usize] = w[1];
            }
            if let Some(&last) = list.last() {
                fat[last as usize] = 0x0FFF_FFFF;
            }
            list
        };
        let mut dir_clusters: Vec<Vec<u32>> = Vec::new();
        for d in 0..self.dirs.len() {
            let bytes = slots_of(d) * 32;
            if d == 0 && kind != FatKind::Fat32 {
                assert!(slots_of(0) <= root_entries, "root directory full");
                dir_clusters.push(Vec::new());
            } else {
                dir_clusters.push(alloc(bytes.div_ceil(cs), false));
            }
        }
        let mut file_clusters: Vec<Vec<Vec<u32>>> = Vec::new();
        for dir in &self.dirs {
            let mut per = Vec::new();
            for e in &dir.entries {
                let n = if e.deleted || e.dir.is_some() {
                    0
                } else {
                    e.data.len().div_ceil(cs)
                };
                per.push(alloc(n, e.fragmented));
            }
            file_clusters.push(per);
        }
        let used_end = data_offset + (next - 2) * cs;

        // The FAT, with the end-of-chain marker of the type.
        let eoc = match kind {
            FatKind::Fat12 => 0x0FFFu32,
            FatKind::Fat16 => 0xFFFF,
            FatKind::Fat32 => 0x0FFF_FFFF,
        };
        let media = match kind {
            FatKind::Fat12 => 0x0FF8u32,
            FatKind::Fat16 => 0xFFF8,
            FatKind::Fat32 => 0x0FFF_FFF8,
        };
        fat[0] = media;
        fat[1] = eoc;
        for v in fat.iter_mut().skip(2) {
            if *v == 0x0FFF_FFFF {
                *v = eoc;
            }
        }
        let mut table = vec![0u8; fat_sectors * bps];
        for (n, &v) in fat.iter().enumerate() {
            match kind {
                FatKind::Fat12 => {
                    let at = n * 3 / 2;
                    if n % 2 == 0 {
                        table[at] = (v & 0xFF) as u8;
                        table[at + 1] = (table[at + 1] & 0xF0) | ((v >> 8) & 0x0F) as u8;
                    } else {
                        table[at] = (table[at] & 0x0F) | ((v & 0x0F) << 4) as u8;
                        table[at + 1] = (v >> 4) as u8;
                    }
                }
                FatKind::Fat16 => {
                    table[n * 2..n * 2 + 2].copy_from_slice(&(v as u16).to_le_bytes())
                }
                FatKind::Fat32 => table[n * 4..n * 4 + 4].copy_from_slice(&v.to_le_bytes()),
            }
        }
        for k in 0..fats {
            let at = fat_offset + k * fat_sectors * bps;
            image[at..at + table.len()].copy_from_slice(&table);
        }

        // Directories and file content.
        let disk_of = |d: usize, pos: usize| -> usize {
            if d == 0 && kind != FatKind::Fat32 {
                root_offset + pos
            } else {
                let c = dir_clusters[d][pos / cs] as usize;
                data_offset + (c - 2) * cs + pos % cs
            }
        };
        let mut items = Vec::new();
        for (d, dir) in self.dirs.iter().enumerate() {
            let mut slots: Vec<[u8; 32]> = Vec::new();
            let first_of = |idx: usize| dir_clusters[idx].first().copied().unwrap_or(0);
            if d != 0 {
                let parent_cluster = self
                    .dirs
                    .iter()
                    .position(|p| p.entries.iter().any(|e| e.dir == Some(d)))
                    .map_or(0, |p| if p == 0 { 0 } else { first_of(p) });
                slots.push(record(*b".          ", 0x10, 0, first_of(d), 0, kind));
                slots.push(record(*b"..         ", 0x10, 0, parent_cluster, 0, kind));
            }
            if d == 0
                && let Some(label) = &self.label
            {
                let mut raw = [b' '; 11];
                raw[..label.len()].copy_from_slice(label.as_bytes());
                slots.push(record(raw, 0x08, 0, 0, 0, kind));
            }
            let mut record_slots = Vec::new();
            for (i, e) in dir.entries.iter().enumerate() {
                if e.long {
                    let sum = short_checksum(&e.short);
                    let mut units: Vec<u16> = e.name.encode_utf16().collect();
                    if !units.len().is_multiple_of(13) {
                        units.push(0);
                    }
                    while !units.len().is_multiple_of(13) {
                        units.push(0xFFFF);
                    }
                    let n = units.len() / 13;
                    for part in (0..n).rev() {
                        let mut b = [0u8; 32];
                        b[0] = (part + 1) as u8 | if part + 1 == n { 0x40 } else { 0 };
                        b[11] = 0x0F;
                        b[13] = sum;
                        let offsets = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                        for (k, &at) in offsets.iter().enumerate() {
                            b[at..at + 2].copy_from_slice(&units[part * 13 + k].to_le_bytes());
                        }
                        if e.deleted {
                            b[0] = 0xE5;
                        }
                        slots.push(b);
                    }
                }
                let first = if let Some(sub) = e.dir {
                    first_of(sub)
                } else {
                    file_clusters[d][i].first().copied().unwrap_or(0)
                };
                let size = if e.dir.is_some() {
                    0
                } else {
                    e.data.len() as u32
                };
                let mut raw = e.short;
                if e.deleted {
                    raw[0] = 0xE5;
                } else if raw[0] == 0xE5 {
                    raw[0] = 0x05;
                }
                record_slots.push(slots.len());
                slots.push(record(raw, e.attr, e.nt_case, first, size, kind));
            }
            let mut bytes = Vec::new();
            for s in &slots {
                bytes.extend_from_slice(s);
            }
            for (pos, chunk) in bytes.chunks(cs.min(bytes.len().max(1))).enumerate() {
                let at = disk_of(d, pos * cs.min(bytes.len().max(1)));
                image[at..at + chunk.len()].copy_from_slice(chunk);
            }
            for (i, e) in dir.entries.iter().enumerate() {
                let path = format!("{}/{}", dir.path, e.name);
                let record = disk_of(d, record_slots[i] * 32) as u64;
                items.push(Item {
                    path,
                    is_dir: e.dir.is_some(),
                    data: e.data.clone(),
                    deleted: e.deleted,
                    hidden: e.attr & 0x06 != 0,
                    record,
                    clusters: file_clusters[d][i].clone(),
                });
            }
            for (i, e) in dir.entries.iter().enumerate() {
                for (k, &c) in file_clusters[d][i].iter().enumerate() {
                    let at = data_offset + (c as usize - 2) * cs;
                    let from = k * cs;
                    let to = (from + cs).min(e.data.len());
                    image[at..at + (to - from)].copy_from_slice(&e.data[from..to]);
                }
            }
        }
        // Items of subfolders carry their cluster chain.
        for item in &mut items {
            if item.is_dir {
                let idx = self.dirs.iter().position(|d| d.path == item.path).unwrap();
                item.clusters = dir_clusters[idx].clone();
            }
        }

        write_boot(
            &mut image,
            kind,
            bps,
            self.spc as usize,
            reserved,
            root_entries,
            total_sectors,
            fat_sectors,
            self.label.as_deref(),
        );
        Built {
            image,
            kind,
            cluster_size: cs as u64,
            data_offset: data_offset as u64,
            fat_offset: fat_offset as u64,
            root_offset: root_offset as u64,
            cluster_count: self.clusters,
            items,
            used_end: used_end as u64,
        }
    }
}

fn record(raw: [u8; 11], attr: u8, nt: u8, first: u32, size: u32, kind: FatKind) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..11].copy_from_slice(&raw);
    b[11] = attr;
    b[12] = nt;
    b[14..16].copy_from_slice(&TIME.to_le_bytes());
    b[16..18].copy_from_slice(&DATE.to_le_bytes());
    b[18..20].copy_from_slice(&DATE.to_le_bytes());
    if kind == FatKind::Fat32 {
        b[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    }
    b[22..24].copy_from_slice(&TIME.to_le_bytes());
    b[24..26].copy_from_slice(&DATE.to_le_bytes());
    b[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    b[28..32].copy_from_slice(&size.to_le_bytes());
    b
}

#[allow(clippy::too_many_arguments)]
fn write_boot(
    image: &mut [u8],
    kind: FatKind,
    bps: usize,
    spc: usize,
    reserved: usize,
    root_entries: usize,
    total_sectors: usize,
    fat_sectors: usize,
    label: Option<&str>,
) {
    let b = &mut image[..512];
    b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    b[3..11].copy_from_slice(b"ATLAS1.0");
    b[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
    b[13] = spc as u8;
    b[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    b[16] = 2;
    b[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
    if total_sectors < 0x10000 && kind != FatKind::Fat32 {
        b[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
    } else {
        b[32..36].copy_from_slice(&(total_sectors as u32).to_le_bytes());
    }
    b[21] = 0xF8;
    let mut name = [b' '; 11];
    let label = label.unwrap_or("NO NAME");
    name[..label.len()].copy_from_slice(label.as_bytes());
    if kind == FatKind::Fat32 {
        b[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
        b[44..48].copy_from_slice(&2u32.to_le_bytes());
        b[66] = 0x29;
        b[67..71].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        b[71..82].copy_from_slice(&name);
        b[82..90].copy_from_slice(b"FAT32   ");
    } else {
        b[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
        b[38] = 0x29;
        b[39..43].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        b[43..54].copy_from_slice(&name);
        b[54..62].copy_from_slice(if kind == FatKind::Fat12 {
            b"FAT12   "
        } else {
            b"FAT16   "
        });
    }
    b[510] = 0x55;
    b[511] = 0xAA;
}

/// The names in [`standard`], as listed, with the file sizes in clusters
/// where it matters.
pub const LONG_NAME: &str = "A long file name.txt";
/// A name with characters outside ASCII.
pub const ACCENTED: &str = "R\u{e9}sum\u{e9}.txt";

/// A volume with a nested folder, a file with a long name, a short-name file
/// with case bits, a fragmented file, a deleted entry, a hidden file, an
/// empty file and a name outside ASCII.
///
/// ```text
/// /docs/A long file name.txt   700 bytes
/// /docs/notes.txt              short entry, lower case bits
/// /docs/deep/a.bin             40 bytes
/// /FRAG.BIN                    fragmented, five clusters less 100 bytes
/// /Gone.txt                    deleted
/// /secret.sys                  hidden and system
/// /EMPTY.DAT                   empty
/// /Résumé.txt                  long entry
/// ```
pub fn standard(kind: FatKind) -> Built {
    standard_builder(kind).build()
}

/// The builder behind [`standard`], for variations.
pub fn standard_builder(kind: FatKind) -> VolumeBuilder {
    let mut b = VolumeBuilder::new(kind);
    let cs = b.bps as usize * b.spc as usize;
    b.label("ATLAS");
    let docs = b.dir(0, "docs");
    b.file(docs, LONG_NAME, &pattern(700, 1));
    b.file(docs, "notes.txt", &pattern(90, 2));
    let deep = b.dir(docs, "deep");
    b.file(deep, "a.bin", &pattern(40, 3));
    b.file_with(
        0,
        "FRAG.BIN",
        &pattern(cs * 5 - 100, 4),
        Opts {
            fragmented: true,
            ..Opts::default()
        },
    );
    b.file_with(
        0,
        "Gone.txt",
        &pattern(10, 5),
        Opts {
            deleted: true,
            ..Opts::default()
        },
    );
    b.file_with(
        0,
        "secret.sys",
        &pattern(20, 6),
        Opts {
            hidden: true,
            system: true,
            ..Opts::default()
        },
    );
    b.file(0, "EMPTY.DAT", &[]);
    b.file(0, ACCENTED, &pattern(300, 7));
    b
}
