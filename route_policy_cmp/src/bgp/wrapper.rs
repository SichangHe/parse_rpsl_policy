use std::{
    io::{self, BufRead},
    path::Path,
    process::Command,
};

use crate::cmd::OutputChild;

use super::*;

/// A line of table dump generated by `bgpdump` from a MRT file.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Line {
    pub raw: String,
    /// Designed to be directly used.
    pub compare: Compare,
    /// Slot used to store the generated report about this line.
    pub report: Option<Vec<Report>>,
}

impl Line {
    pub fn new(raw: String, compare: Compare, report: Option<Vec<Report>>) -> Self {
        Self {
            raw,
            compare,
            report,
        }
    }

    /// Parse `raw` into a [`Line`].
    pub fn from_raw(raw: String) -> Result<Self> {
        let compare = Compare::with_line_dump(&raw)?;
        Ok(Self::new(raw, compare, None))
    }

    /// Generate report on `self` and store in `self.report`.
    pub fn check(&mut self, dump: &QueryDump) {
        self.report = Some(self.compare.check(dump));
    }
}

/// Read MRT file at `path` using the `bgpdump` executable.
pub fn parse_mrt<P>(path: P) -> Result<Vec<Line>>
where
    P: AsRef<Path>,
{
    let output_child = read_mrt(path)?;
    pack_lines(output_child)
}

/// Pack all the [`Line`]s from `output_child`'s output.
pub fn pack_lines(mut output_child: OutputChild) -> Result<Vec<Line>> {
    let mut lines = Vec::new();
    let mut line = String::new();

    while output_child.stdout.read_line(&mut line)? > 0 {
        let raw = mem::take(&mut line);
        lines.push(Line::from_raw(raw)?);
    }
    Ok(lines)
}

/// Start a `bgpdump` process that reads `path`.
pub fn read_mrt<P>(path: P) -> Result<OutputChild, io::Error>
where
    P: AsRef<Path>,
{
    OutputChild::new(Command::new("bgpdump").arg("-m").arg(path.as_ref()))
}
