#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMetadata {
    pub version: u64,
    pub parent_cid: Option<String>,
}
