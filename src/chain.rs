// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Cluster chains, turned into byte runs and read as a [`BlockSource`].

use std::sync::Arc;

use super::boot::Geometry;
use super::table::{FatTable, Next};
use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};

/// Most bytes a directory's chain may cover.
pub const MAX_DIR_BYTES: u64 = 256 * 1024 * 1024;

const STRUCTURE: &str = "cluster chain";

/// How far [`Chain::follow`] goes.
#[derive(Debug, Clone, Copy)]
pub enum Limit {
    /// Stop quietly after this many clusters (a file: its size says how many
    /// it has).
    Truncate(u64),
    /// Follow to the end of the chain; past this many clusters is damage (a
    /// directory has no size).
    Directory(u64),
}

/// A run of bytes of a chain, contiguous on the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// Offset of the run in the chain's content.
    pub file_start: u64,
    /// Offset of the run in the volume.
    pub disk: u64,
    /// Length of the run in bytes; never 0.
    pub len: u64,
}

/// The bytes of a file or directory: its clusters, in order, as runs.
///
/// Reading past what the chain covers fails with the damage that cut the
/// chain short, so the part before it stays readable.
pub struct Chain {
    source: Arc<dyn BlockSource>,
    runs: Vec<Run>,
    size: u64,
    covered: u64,
    broken: Option<Corruption>,
}

fn corrupt(location: Location, kind: CorruptKind) -> Corruption {
    Corruption::new(STRUCTURE, location, kind)
}

impl Chain {
    /// A chain of no bytes.
    pub fn empty(source: Arc<dyn BlockSource>) -> Self {
        Self {
            source,
            runs: Vec::new(),
            size: 0,
            covered: 0,
            broken: None,
        }
    }

    /// A chain from runs already worked out (exFAT follows its own FAT).
    /// The runs are in content order, never empty, and start at 0 with no
    /// gaps. `broken` is the damage that ended the chain, reported when a
    /// read reaches it.
    pub fn from_runs(
        source: Arc<dyn BlockSource>,
        runs: Vec<Run>,
        broken: Option<Corruption>,
    ) -> Self {
        let covered = runs
            .last()
            .map_or(0, |r| r.file_start.saturating_add(r.len));
        Self {
            source,
            runs,
            size: covered,
            covered,
            broken,
        }
    }

    /// `len` bytes at `offset` of the volume as one run (the fixed root
    /// directory of FAT12/16).
    pub fn region(source: Arc<dyn BlockSource>, offset: u64, len: u64) -> Self {
        let runs = if len == 0 {
            Vec::new()
        } else {
            vec![Run {
                file_start: 0,
                disk: offset,
                len,
            }]
        };
        Self {
            source,
            runs,
            size: len,
            covered: len,
            broken: None,
        }
    }

    /// Follows the chain that starts at `first`.
    ///
    /// Damage (a bad cluster, a free cluster, a value out of range, a loop)
    /// ends the chain and is kept to be reported when a read reaches it. An
    /// `Err` is only a failure to read the FAT. A loop is found with Brent's
    /// algorithm, with no table of visited clusters; the walk is also cut
    /// at the volume's cluster count.
    pub fn follow(
        geo: &Geometry,
        table: &FatTable,
        source: Arc<dyn BlockSource>,
        first: u32,
        limit: Limit,
    ) -> Result<Self> {
        let (max, truncate) = match limit {
            Limit::Truncate(n) => (n, true),
            Limit::Directory(n) => (n, false),
        };
        let mut chain = Self::empty(source);
        if truncate && max == 0 {
            return Ok(chain);
        }
        let cs = u64::from(geo.cluster_size);
        let mut count: u64 = 0;
        let mut cur = first;
        let (mut tortoise, mut power, mut lam) = (first, 1u64, 0u64);
        let broken = loop {
            let Some(disk) = geo.cluster_offset(cur) else {
                break Some(corrupt(
                    Location::Object(u64::from(cur)),
                    CorruptKind::OutOfRange {
                        field: "cluster",
                        value: u64::from(cur),
                        limit_name: "last cluster",
                        limit: u64::from(geo.last_cluster()),
                    },
                ));
            };
            let file_start = count.saturating_mul(cs);
            match chain.runs.last_mut() {
                Some(last) if last.disk.checked_add(last.len) == Some(disk) => {
                    last.len = last.len.saturating_add(cs);
                }
                _ => chain.runs.push(Run {
                    file_start,
                    disk,
                    len: cs,
                }),
            }
            count = count.saturating_add(1);
            chain.covered = file_start.saturating_add(cs);
            if truncate && count >= max {
                break None;
            }
            match table.next(cur)? {
                Next::End => break None,
                Next::Data(n) => {
                    if !truncate && count >= max {
                        break Some(corrupt(
                            Location::Object(u64::from(first)),
                            CorruptKind::LimitExceeded {
                                what: "directory size",
                                limit: MAX_DIR_BYTES,
                            },
                        ));
                    }
                    if count > u64::from(geo.cluster_count) || n == tortoise {
                        break Some(corrupt(
                            Location::Object(u64::from(first)),
                            CorruptKind::Loop {
                                what: "cluster chain",
                            },
                        ));
                    }
                    lam = lam.saturating_add(1);
                    if lam == power {
                        tortoise = n;
                        power = power.saturating_mul(2);
                        lam = 0;
                    }
                    cur = n;
                }
                Next::Free | Next::Bad | Next::Invalid(_) => {
                    break Some(corrupt(
                        Location::Object(u64::from(cur)),
                        CorruptKind::Other("chain runs into a free, bad or invalid cluster"),
                    ));
                }
            }
        };
        chain.size = chain.covered;
        chain.broken = broken;
        Ok(chain)
    }

    /// The same chain with `size` as its length. Bytes past what the chain
    /// covers fail to read.
    #[must_use]
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// The runs, in content order, merged where they touch on the volume.
    pub fn runs(&self) -> &[Run] {
        &self.runs
    }

    /// The damage that ended the chain early, if any.
    pub fn broken(&self) -> Option<&Corruption> {
        self.broken.as_ref()
    }

    /// The volume offset of content offset `pos`, and the bytes left in its
    /// run from there. `None` past what the chain covers.
    pub fn locate(&self, pos: u64) -> Option<(u64, u64)> {
        let after = self.runs.partition_point(|r| r.file_start <= pos);
        let run = self.runs.get(after.checked_sub(1)?)?;
        let into = pos.checked_sub(run.file_start)?;
        if into >= run.len {
            return None;
        }
        Some((run.disk.checked_add(into)?, run.len.saturating_sub(into)))
    }

    /// The error for a read that reaches `pos`, where the chain has no more.
    fn gap(&self, pos: u64) -> Error {
        self.broken
            .clone()
            .unwrap_or_else(|| {
                corrupt(
                    Location::Byte(pos),
                    CorruptKind::Truncated {
                        needed: self.size,
                        available: self.covered,
                    },
                )
            })
            .into()
    }
}

impl BlockSource for Chain {
    fn len(&self) -> u64 {
        self.size
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.size)?;
        let mut pos = offset;
        let mut done = 0usize;
        // Each pass reads at least one byte (runs are never empty).
        while done < buf.len() {
            let Some((disk, avail)) = self.locate(pos) else {
                return Err(self.gap(pos));
            };
            let left = buf.len().saturating_sub(done);
            let take = usize::try_from(avail).map_or(left, |a| a.min(left));
            let end = done.saturating_add(take);
            let Some(dst) = buf.get_mut(done..end) else {
                return Err(self.gap(pos));
            };
            self.source.read_at(disk, dst)?;
            done = end;
            pos = pos.saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
        }
        Ok(())
    }
}
