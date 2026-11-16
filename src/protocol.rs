use anyhow::{ensure, Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u64 = 1;
pub const REQUEST_LIMIT: usize = 16 * 1024;
pub const RESPONSE_LIMIT: usize = 16 * 1024 * 1024;

pub fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("Missing string field: {field}"))
}

pub fn unsigned(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .with_context(|| format!("Missing unsigned integer: {field}"))
}

pub fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

pub fn valid_sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

pub async fn read<R: AsyncBufRead + Unpin>(reader: &mut R, limit: usize) -> Result<Value> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        ensure!(
            !buffer.is_empty(),
            "Connection closed before complete response/request"
        );
        let end = buffer.iter().position(|&b| b == b'\n');
        let count = end.map_or(buffer.len(), |i| i + 1);
        ensure!(
            line.len() + count <= limit,
            "Protocol message exceeds size limit"
        );
        line.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if end.is_some() {
            break;
        }
    }
    let result: Value = serde_json::from_slice(&line)?;
    ensure!(result.is_object(), "Protocol message must be a JSON object");
    Ok(result)
}

pub async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Value,
    limit: usize,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() < limit, "Protocol message exceeds size limit");
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
