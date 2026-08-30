/// The letter case used when rendering textual output such as hex digests.
#[derive(Debug, Default)]
pub enum Case {
    Upper,
    #[default]
    Lower,
}
