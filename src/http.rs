//! Optional HTTP control transport for both native and Wasm-agent execution.
use crate::{protocol, request, Server};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming, server::conn::http1, service::service_fn, Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{json, Value};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::net::TcpStream;

fn response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    let mut data = serde_json::to_vec(&value).expect("JSON response");
    let status = if data.len() > protocol::RESPONSE_LIMIT {
        data = br#"{"status":"error","error":"response too large","execution_outcome":"unknown"}"#
            .to_vec();
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        status
    };
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store");
    // Rejected requests may still have unread bodies. Never reuse those sockets.
    if !status.is_success() {
        builder = builder.header("Connection", "close");
    }
    builder
        .body(Full::new(Bytes::from(data)))
        .expect("HTTP response")
}

async fn handle(
    server: Arc<Server>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let credential = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_owned();
    let authorized = crate::tenancy::same_token(&credential, &server.token)
        || server
            .shared
            .policy
            .as_ref()
            .is_some_and(|p| p.authenticate(&credential).is_some());
    if !authorized {
        return Ok(response(
            StatusCode::UNAUTHORIZED,
            json!({"error":"unauthorized"}),
        ));
    }
    let op = match (req.method(), req.uri().path(), req.uri().query()) {
        (&Method::POST, "/v1/run", None) => "run",
        (&Method::GET, "/v1/stats", None) => "stats",
        _ => {
            return Ok(response(
                StatusCode::NOT_FOUND,
                json!({"error":"endpoint not found"}),
            ))
        }
    };
    if server.shared.policy.is_some()
        && ((op == "stats" && !crate::tenancy::same_token(&credential, &server.token))
            || (op == "run" && crate::tenancy::same_token(&credential, &server.token)))
    {
        return Ok(response(
            StatusCode::FORBIDDEN,
            json!({"error":"credential is not permitted for this operation"}),
        ));
    }
    let mut value = if op == "stats" {
        if req.headers().contains_key("transfer-encoding")
            || req
                .headers()
                .get("content-length")
                .is_some_and(|v| v != "0")
        {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"stats takes no body"}),
            ));
        }
        json!({})
    } else {
        let body = match tokio::time::timeout(
            Duration::from_secs(10),
            Limited::new(req.into_body(), protocol::REQUEST_LIMIT).collect(),
        )
        .await
        {
            Ok(Ok(body)) => body.to_bytes(),
            Ok(Err(_)) => {
                return Ok(response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({"error":"invalid or oversized body"}),
                ))
            }
            Err(_) => {
                return Ok(response(
                    StatusCode::REQUEST_TIMEOUT,
                    json!({"error":"body read timeout"}),
                ))
            }
        };
        match serde_json::from_slice::<Value>(&body) {
            Ok(value) if value.is_object() => value,
            _ => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"body must be a JSON object"}),
                ))
            }
        }
    };
    value["op"] = json!(op);
    // The public token is only accepted through the Authorization header.
    value["token"] = json!(credential);
    let value = request(&server, value)
        .await
        .unwrap_or_else(|e| json!({"status":"error","error":format!("{e:#}")}));
    Ok(response(StatusCode::OK, value))
}

pub async fn connection(server: Arc<Server>, stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    server
        .http_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    http1::Builder::new()
        .keep_alive(server.shared.args.http_keep_alive)
        .max_buf_size(protocol::REQUEST_LIMIT)
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| handle(server.clone(), req)),
        )
        .await?;
    Ok(())
}
