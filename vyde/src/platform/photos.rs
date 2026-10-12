use std::path::{Path, PathBuf};

/// Maximum file size accepted before sending it to Identity.
pub const MAX_PHOTO_BYTES: usize = 5 * 1024 * 1024;

/// Expand a leading home-directory shorthand.
pub fn expand_home(path: &str) -> PathBuf {
    path.strip_prefix("~/").map_or_else(
        || PathBuf::from(path),
        |rest| {
            PathBuf::from(format!(
                "{}/{}",
                std::env::var("HOME").unwrap_or_default(),
                rest
            ))
        },
    )
}

/// Guess a request content type from the local filename.
pub fn content_type_for(path: &Path) -> String {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
    .to_owned()
}
