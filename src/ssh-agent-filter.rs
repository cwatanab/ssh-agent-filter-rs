use clap::Parser;
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_RSA_IDENTITIES: u8 = 1;
const SSH_AGENT_RSA_IDENTITIES_ANSWER: u8 = 2;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES: u8 = 9;

#[derive(Parser, Debug)]
#[command(name = "ssh-agent-filter", version, about = "Filtering proxy for ssh-agent")]
struct Cli {
    #[arg(short = 'A', long = "all-confirmed", help = "allow all other keys with confirmation")]
    all_confirmed: bool,

    #[arg(short = 'c', long = "comment", help = "key specified by comment")]
    comment: Vec<String>,

    #[arg(short = 'C', long = "comment-confirmed", help = "key specified by comment, with confirmation")]
    comment_confirmed: Vec<String>,

    #[arg(short = 'd', long = "debug", help = "show some debug info, don't fork")]
    debug: bool,

    #[arg(short = 'f', long = "fingerprint", help = "key specified by pubkey's hex-encoded md5 fingerprint")]
    fingerprint: Vec<String>,

    #[arg(short = 'F', long = "fingerprint-confirmed", help = "key specified by pubkey's hex-encoded md5 fingerprint, with confirmation")]
    fingerprint_confirmed: Vec<String>,

    #[arg(short = 'k', long = "key", help = "key specified by base64-encoded pubkey")]
    key: Vec<String>,

    #[arg(short = 'K', long = "key-confirmed", help = "key specified by base64-encoded pubkey, with confirmation")]
    key_confirmed: Vec<String>,

    #[arg(short = 'n', long = "name", help = "name for this instance of ssh-agent-filter, for confirmation purposes")]
    name: Option<String>,

    #[arg(long = "out-pipe", help = "Windows only: Path of the named pipe to listen on (e.g. \\\\.\\pipe\\openssh-ssh-agent-filtered)")]
    out_pipe: Option<String>,

    #[arg(long = "in-pipe", help = "Windows only: Path of the upstream named pipe (e.g. \\\\.\\pipe\\openssh-ssh-agent)")]
    in_pipe: Option<String>,

    #[arg(long = "out-sock", help = "Unix only: Path of the Unix socket to listen on")]
    out_sock: Option<String>,

    #[arg(long = "in-sock", help = "Unix only: Path of the upstream Unix socket")]
    in_sock: Option<String>,
}

enum AgentStream {
    #[cfg(windows)]
    NamedPipeServer(tokio::net::windows::named_pipe::NamedPipeServer),
    #[cfg(windows)]
    NamedPipeClient(tokio::net::windows::named_pipe::NamedPipeClient),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl AsyncRead for AgentStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(windows)]
            AgentStream::NamedPipeServer(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(windows)]
            AgentStream::NamedPipeClient(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            AgentStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AgentStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(windows)]
            AgentStream::NamedPipeServer(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(windows)]
            AgentStream::NamedPipeClient(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            AgentStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(windows)]
            AgentStream::NamedPipeServer(s) => Pin::new(s).poll_flush(cx),
            #[cfg(windows)]
            AgentStream::NamedPipeClient(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            AgentStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(windows)]
            AgentStream::NamedPipeServer(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(windows)]
            AgentStream::NamedPipeClient(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            AgentStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

struct BufferReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BufferReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, &'static str> {
        if self.offset + 1 > self.data.len() {
            return Err("unexpected end of buffer");
        }
        let val = self.data[self.offset];
        self.offset += 1;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32, &'static str> {
        if self.offset + 4 > self.data.len() {
            return Err("unexpected end of buffer");
        }
        let bytes = &self.data[self.offset..self.offset + 4];
        let val = u32::from_be_bytes(bytes.try_into().unwrap());
        self.offset += 4;
        Ok(val)
    }

    fn read_u64(&mut self) -> Result<u64, &'static str> {
        if self.offset + 8 > self.data.len() {
            return Err("unexpected end of buffer");
        }
        let bytes = &self.data[self.offset..self.offset + 8];
        let val = u64::from_be_bytes(bytes.try_into().unwrap());
        self.offset += 8;
        Ok(val)
    }

    fn read_string(&mut self) -> Result<&'a [u8], &'static str> {
        let len = self.read_u32()? as usize;
        if self.offset + len > self.data.len() {
            return Err("unexpected end of buffer");
        }
        let val = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(val)
    }
}

struct BufferWriter {
    data: Vec<u8>,
}

impl BufferWriter {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn write_u8(&mut self, val: u8) {
        self.data.push(val);
    }

    fn write_u32(&mut self, val: u32) {
        self.data.extend_from_slice(&val.to_be_bytes());
    }

    fn write_string(&mut self, val: &[u8]) {
        self.write_u32(val.len() as u32);
        self.data.extend_from_slice(val);
    }

    fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let len = reader.read_u32().await?;
    if len > 256 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "packet too large",
        ));
    }
    let mut buf = vec![0; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> std::io::Result<()> {
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

fn canonicalize_fingerprint(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::prelude::BASE64_STANDARD.encode(bytes)
}

fn md5_hex(bytes: &[u8]) -> String {
    let digest = md5::compute(bytes);
    hex::encode(digest.0)
}

fn dissect_pam_ssh_agent_auth(session_id: &[u8]) -> Option<String> {
    let mut reader = BufferReader::new(session_id);
    let auth_type = reader.read_u32().ok()?;
    if auth_type != 101 {
        return None;
    }
    let _cookie = reader.read_string().ok()?;
    let user = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let ruser = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let pam_service = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let pwd = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let action_bytes = reader.read_string().ok()?;
    let hostname = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let timestamp = reader.read_u64().ok()?;

    let single_user = if user == ruser {
        user
    } else {
        format!("{} ({})", user, ruser)
    };

    let mut additional = format!(
        "User '{}' wants to use '{}' in '{}'",
        single_user, pam_service, pwd
    );

    let mut action_reader = BufferReader::new(action_bytes);
    if let Ok(argc) = action_reader.read_u32() {
        if argc > 0 {
            additional.push_str(" to run");
            for _ in 0..argc {
                if let Ok(arg_bytes) = action_reader.read_string() {
                    additional.push_str(&format!(" {}", String::from_utf8_lossy(arg_bytes)));
                }
            }
        }
    }

    additional.push_str(&format!(" on {}.\n", hostname));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let timediff = now.checked_sub(timestamp).unwrap_or(0);
    additional.push_str(&format!("The request was generated {} seconds ago.\n", timediff));

    Some(additional)
}

fn dissect_auth_data_ssh(data: &[u8]) -> Option<String> {
    let mut reader = BufferReader::new(data);
    let session_identifier = reader.read_string().ok()?;
    let request_type = reader.read_u8().ok()?;
    let username = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let service_name = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let method = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let should_be_true = reader.read_u8().ok()?;
    let _algo = String::from_utf8_lossy(reader.read_string().ok()?).into_owned();
    let _pubkey = reader.read_string().ok()?;

    if request_type != 60 || method != "publickey" || should_be_true == 0 {
        return None;
    }

    let mut desc = format!(
        "The request is for an ssh connection as user '{}' with service name '{}'.",
        username, service_name
    );

    if service_name == "pam_ssh_agent_auth" {
        if let Some(pam_desc) = dissect_pam_ssh_agent_auth(session_identifier) {
            desc = pam_desc;
        }
    }

    Some(desc)
}

#[cfg(windows)]
fn confirm_gui(question: &str) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let text: Vec<u16> = OsStr::new(question)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let caption: Vec<u16> = OsStr::new("ssh-agent-filter confirmation")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let utype = 0x00000004 | 0x00000020 | 0x00010000 | 0x00040000;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxTimeoutW(
            hwnd: *mut std::ffi::c_void,
            lpText: *const u16,
            lpCaption: *const u16,
            uType: u32,
            wLanguageId: u16,
            dwMilliseconds: u32,
        ) -> i32;
    }

    let ret = unsafe {
        MessageBoxTimeoutW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            utype,
            0,
            15000, // 15 seconds timeout
        )
    };

    ret == 6
}

#[cfg(unix)]
async fn confirm_askpass(question: &str) -> bool {
    let askpass = std::env::var("SSH_ASKPASS").unwrap_or_else(|_| "ssh-askpass".to_string());
    let status = tokio::process::Command::new(askpass)
        .arg(question)
        .status()
        .await;
    match status {
        Ok(s) => s.success(),
        Err(e) => {
            eprintln!("Failed to execute SSH_ASKPASS command: {}", e);
            false
        }
    }
}

async fn confirm(question: String) -> bool {
    #[cfg(windows)]
    {
        tokio::task::spawn_blocking(move || {
            confirm_gui(&question)
        }).await.unwrap_or(false)
    }
    #[cfg(unix)]
    {
        confirm_askpass(&question).await
    }
}

#[cfg(windows)]
async fn connect_upstream(pipe_path: &str) -> std::io::Result<AgentStream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let client = ClientOptions::new().open(pipe_path)?;
    Ok(AgentStream::NamedPipeClient(client))
}

#[cfg(unix)]
async fn connect_upstream(sock_path: &str) -> std::io::Result<AgentStream> {
    let stream = tokio::net::UnixStream::connect(sock_path).await?;
    Ok(AgentStream::Unix(stream))
}

async fn setup_filters(
    upstream_path: &str,
    allowed_comments: &[String],
    confirmed_comments: &[String],
    allowed_md5s: &[String],
    confirmed_md5s: &[String],
    allowed_b64s: &[String],
    confirmed_b64s: &[String],
    all_confirmed: bool,
    debug: bool,
) -> Result<(HashSet<Vec<u8>>, HashMap<Vec<u8>, String>), Box<dyn std::error::Error>> {
    let mut upstream = connect_upstream(upstream_path).await?;
    
    let mut req_writer = BufferWriter::new();
    req_writer.write_u8(SSH2_AGENTC_REQUEST_IDENTITIES);
    write_packet(&mut upstream, &req_writer.into_inner()).await?;
    
    let resp = read_packet(&mut upstream).await?;
    let mut reader = BufferReader::new(&resp);
    let resp_type = reader.read_u8()?;
    if resp_type != SSH2_AGENT_IDENTITIES_ANSWER {
        return Err("Unexpected response type from upstream agent".into());
    }
    
    let key_count = reader.read_u32()?;
    let mut allowed_keys = HashSet::new();
    let mut confirmed_keys = HashMap::new();
    
    let mut matched_comments = HashSet::new();
    let mut matched_md5s = HashSet::new();
    let mut matched_b64s = HashSet::new();
    
    for _ in 0..key_count {
        let key = reader.read_string()?;
        let comment_bytes = reader.read_string()?;
        let comment = String::from_utf8_lossy(comment_bytes).into_owned();
        
        let b64 = base64_encode(key);
        let md5 = md5_hex(key);
        
        if debug {
            eprintln!("Loaded key comment: {}", comment);
            eprintln!("Loaded key md5: {}", md5);
            eprintln!("Loaded key b64: {}", b64);
        }
        
        let is_allowed = allowed_comments.contains(&comment)
            || allowed_md5s.contains(&md5)
            || allowed_b64s.contains(&b64);
            
        if is_allowed {
            if debug {
                eprintln!("-> Key allowed directly");
            }
            allowed_keys.insert(key.to_vec());
            
            if allowed_comments.contains(&comment) {
                matched_comments.insert(comment.clone());
            }
            if allowed_md5s.contains(&md5) {
                matched_md5s.insert(md5.clone());
            }
            if allowed_b64s.contains(&b64) {
                matched_b64s.insert(b64.clone());
            }
        } else {
            let is_confirmed = confirmed_comments.contains(&comment)
                || confirmed_md5s.contains(&md5)
                || confirmed_b64s.contains(&b64)
                || all_confirmed;
                
            if is_confirmed {
                if debug {
                    eprintln!("-> Key allowed with confirmation");
                }
                confirmed_keys.insert(key.to_vec(), comment.clone());
                
                if confirmed_comments.contains(&comment) {
                    matched_comments.insert(comment.clone());
                }
                if confirmed_md5s.contains(&md5) {
                    matched_md5s.insert(md5.clone());
                }
                if confirmed_b64s.contains(&b64) {
                    matched_b64s.insert(b64.clone());
                }
            }
        }
    }
    
    // Warn about unmatched configuration entries
    for c in allowed_comments {
        if !matched_comments.contains(c) {
            eprintln!("Warning: Allowed key specified by comment '{}' was not found in the upstream agent.", c);
        }
    }
    for c in confirmed_comments {
        if !matched_comments.contains(c) {
            eprintln!("Warning: Confirmed key specified by comment '{}' was not found in the upstream agent.", c);
        }
    }
    for m in allowed_md5s {
        if !matched_md5s.contains(m) {
            eprintln!("Warning: Allowed key specified by fingerprint '{}' was not found in the upstream agent.", m);
        }
    }
    for m in confirmed_md5s {
        if !matched_md5s.contains(m) {
            eprintln!("Warning: Confirmed key specified by fingerprint '{}' was not found in the upstream agent.", m);
        }
    }
    for b in allowed_b64s {
        if !matched_b64s.contains(b) {
            let display_b = if b.len() > 20 { format!("{}...", &b[..20]) } else { b.clone() };
            eprintln!("Warning: Allowed key specified by base64 pubkey '{}' was not found in the upstream agent.", display_b);
        }
    }
    for b in confirmed_b64s {
        if !matched_b64s.contains(b) {
            let display_b = if b.len() > 20 { format!("{}...", &b[..20]) } else { b.clone() };
            eprintln!("Warning: Confirmed key specified by base64 pubkey '{}' was not found in the upstream agent.", display_b);
        }
    }
    
    Ok((allowed_keys, confirmed_keys))
}

async fn handle_connection(
    mut client: AgentStream,
    upstream_path: &str,
    allowed_keys: HashSet<Vec<u8>>,
    confirmed_keys: HashMap<Vec<u8>, String>,
    all_confirmed: bool,
    saf_name: Option<String>,
) -> std::io::Result<()> {
    loop {
        let req_packet = match read_packet(&mut client).await {
            Ok(pkt) => pkt,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e),
        };

        if req_packet.is_empty() {
            continue;
        }

        let mut reader = BufferReader::new(&req_packet);
        let msg_type = match reader.read_u8() {
            Ok(t) => t,
            Err(_) => {
                let mut writer = BufferWriter::new();
                writer.write_u8(SSH_AGENT_FAILURE);
                let _ = write_packet(&mut client, &writer.into_inner()).await;
                continue;
            }
        };

        match msg_type {
            SSH2_AGENTC_REQUEST_IDENTITIES => {
                let mut upstream = match connect_upstream(upstream_path).await {
                    Ok(u) => u,
                    Err(e) => {
                        eprintln!("Failed to connect to upstream ssh-agent: {}", e);
                        let mut writer = BufferWriter::new();
                        writer.write_u8(SSH_AGENT_FAILURE);
                        let _ = write_packet(&mut client, &writer.into_inner()).await;
                        continue;
                    }
                };
                if let Err(e) = write_packet(&mut upstream, &req_packet).await {
                    eprintln!("Failed to write to upstream ssh-agent: {}", e);
                    let mut writer = BufferWriter::new();
                    writer.write_u8(SSH_AGENT_FAILURE);
                    let _ = write_packet(&mut client, &writer.into_inner()).await;
                    continue;
                }
                
                let resp_packet = match read_packet(&mut upstream).await {
                    Ok(pkt) => pkt,
                    Err(e) => {
                        eprintln!("Failed to read from upstream ssh-agent: {}", e);
                        let mut writer = BufferWriter::new();
                        writer.write_u8(SSH_AGENT_FAILURE);
                        let _ = write_packet(&mut client, &writer.into_inner()).await;
                        continue;
                    }
                };
                let mut resp_reader = BufferReader::new(&resp_packet);
                let resp_type = match resp_reader.read_u8() {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Malformed response type from upstream agent: {}", e);
                        let mut writer = BufferWriter::new();
                        writer.write_u8(SSH_AGENT_FAILURE);
                        let _ = write_packet(&mut client, &writer.into_inner()).await;
                        continue;
                    }
                };
                if resp_type != SSH2_AGENT_IDENTITIES_ANSWER {
                    let _ = write_packet(&mut client, &resp_packet).await;
                    continue;
                }
                let key_count = match resp_reader.read_u32() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Malformed response key count from upstream agent: {}", e);
                        let mut writer = BufferWriter::new();
                        writer.write_u8(SSH_AGENT_FAILURE);
                        let _ = write_packet(&mut client, &writer.into_inner()).await;
                        continue;
                    }
                };
                let mut filtered_keys = Vec::new();
                let mut parse_error = false;
                for _ in 0..key_count {
                    let key = match resp_reader.read_string() {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("Malformed response key from upstream agent: {}", e);
                            parse_error = true;
                            break;
                        }
                    };
                    let comment = match resp_reader.read_string() {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Malformed response comment from upstream agent: {}", e);
                            parse_error = true;
                            break;
                        }
                    };
                    if allowed_keys.contains(key) || confirmed_keys.contains_key(key) {
                        filtered_keys.push((key.to_vec(), comment.to_vec()));
                    }
                }
                if parse_error {
                    let mut writer = BufferWriter::new();
                    writer.write_u8(SSH_AGENT_FAILURE);
                    let _ = write_packet(&mut client, &writer.into_inner()).await;
                    continue;
                }
                
                let mut writer = BufferWriter::new();
                writer.write_u8(SSH2_AGENT_IDENTITIES_ANSWER);
                writer.write_u32(filtered_keys.len() as u32);
                for (key, comment) in filtered_keys {
                    writer.write_string(&key);
                    writer.write_string(&comment);
                }
                write_packet(&mut client, &writer.into_inner()).await?;
            }
            SSH2_AGENTC_SIGN_REQUEST => {
                let key = match reader.read_string() {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("Malformed sign request key: {}", e);
                        let mut writer = BufferWriter::new();
                        writer.write_u8(SSH_AGENT_FAILURE);
                        let _ = write_packet(&mut client, &writer.into_inner()).await;
                        continue;
                    }
                };
                let data = match reader.read_string() {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Malformed sign request data: {}", e);
                        let mut writer = BufferWriter::new();
                        writer.write_u8(SSH_AGENT_FAILURE);
                        let _ = write_packet(&mut client, &writer.into_inner()).await;
                        continue;
                    }
                };

                let mut allow = false;
                if allowed_keys.contains(key) {
                    allow = true;
                } else if let Some(comment) = confirmed_keys.get(key).cloned().or_else(|| {
                    if all_confirmed {
                        Some("Unknown key (catch-all)".to_string())
                    } else {
                        None
                    }
                }) {
                    let desc = dissect_auth_data_ssh(data)
                        .unwrap_or_else(|| "The request format is unknown.".to_string());
                    let mut question = "Something behind the ssh-agent-filter".to_string();
                    if let Some(ref name) = saf_name {
                        question.push_str(&format!(" named '{}'", name));
                    }
                    question.push_str(&format!(" requested use of the key named '{}'.\n", comment));
                    question.push_str(&desc);

                    allow = confirm(question).await;
                }

                if allow {
                    let mut upstream = match connect_upstream(upstream_path).await {
                        Ok(u) => u,
                        Err(e) => {
                            eprintln!("Failed to connect to upstream ssh-agent: {}", e);
                            let mut writer = BufferWriter::new();
                            writer.write_u8(SSH_AGENT_FAILURE);
                            let _ = write_packet(&mut client, &writer.into_inner()).await;
                            continue;
                        }
                    };
                    if let Err(e) = write_packet(&mut upstream, &req_packet).await {
                        eprintln!("Failed to write to upstream ssh-agent: {}", e);
                        let mut writer = BufferWriter::new();
                        writer.write_u8(SSH_AGENT_FAILURE);
                        let _ = write_packet(&mut client, &writer.into_inner()).await;
                        continue;
                    }
                    let resp_packet = match read_packet(&mut upstream).await {
                        Ok(pkt) => pkt,
                        Err(e) => {
                            eprintln!("Failed to read from upstream ssh-agent: {}", e);
                            let mut writer = BufferWriter::new();
                            writer.write_u8(SSH_AGENT_FAILURE);
                            let _ = write_packet(&mut client, &writer.into_inner()).await;
                            continue;
                        }
                    };
                    write_packet(&mut client, &resp_packet).await?;
                } else {
                    let mut writer = BufferWriter::new();
                    writer.write_u8(SSH_AGENT_FAILURE);
                    write_packet(&mut client, &writer.into_inner()).await?;
                }
            }
            SSH_AGENTC_REQUEST_RSA_IDENTITIES => {
                let mut writer = BufferWriter::new();
                writer.write_u8(SSH_AGENT_RSA_IDENTITIES_ANSWER);
                writer.write_u32(0);
                write_packet(&mut client, &writer.into_inner()).await?;
            }
            SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES => {
                let mut writer = BufferWriter::new();
                writer.write_u8(SSH_AGENT_SUCCESS);
                write_packet(&mut client, &writer.into_inner()).await?;
            }
            _ => {
                let mut writer = BufferWriter::new();
                writer.write_u8(SSH_AGENT_FAILURE);
                write_packet(&mut client, &writer.into_inner()).await?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
async fn run_listener(
    pipe_path: &str,
    upstream_path: String,
    allowed_keys: HashSet<Vec<u8>>,
    confirmed_keys: HashMap<Vec<u8>, String>,
    all_confirmed: bool,
    saf_name: Option<String>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_path)?;

    println!("Listening on Named Pipe: {}", pipe_path);
    println!("$env:SSH_AUTH_SOCK='{}'", pipe_path);
    println!("SSH_AUTH_SOCK='{}'; export SSH_AUTH_SOCK;", pipe_path);

    loop {
        server.connect().await?;
        let client_stream = AgentStream::NamedPipeServer(server);

        let upstream = upstream_path.clone();
        let allowed = allowed_keys.clone();
        let confirmed = confirmed_keys.clone();
        let name = saf_name.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, &upstream, allowed, confirmed, all_confirmed, name).await {
                eprintln!("Connection handling error: {}", e);
            }
        });

        server = ServerOptions::new().create(pipe_path)?;
    }
}

#[cfg(unix)]
async fn run_listener(
    sock_path: &str,
    upstream_path: String,
    allowed_keys: HashSet<Vec<u8>>,
    confirmed_keys: HashMap<Vec<u8>, String>,
    all_confirmed: bool,
    saf_name: Option<String>,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(sock_path);

    let listener = tokio::net::UnixListener::bind(sock_path)?;
    println!("Listening on Unix Socket: {}", sock_path);
    println!("SSH_AUTH_SOCK='{}'; export SSH_AUTH_SOCK;", sock_path);
    println!("SSH_AGENT_PID='{}'; export SSH_AGENT_PID;", std::process::id());

    loop {
        let (stream, _) = listener.accept().await?;
        let client_stream = AgentStream::Unix(stream);

        let upstream = upstream_path.clone();
        let allowed = allowed_keys.clone();
        let confirmed = confirmed_keys.clone();
        let name = saf_name.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, &upstream, allowed, confirmed, all_confirmed, name).await {
                eprintln!("Connection handling error: {}", e);
            }
        });
    }
}

#[cfg(unix)]
extern "C" {
    fn fork() -> i32;
    fn setsid() -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
}

#[cfg(unix)]
fn daemonize(listen_path: &str) {
    unsafe {
        let pid = fork();
        if pid < 0 {
            eprintln!("fork failed");
            std::process::exit(1);
        }
        if pid > 0 {
            println!("SSH_AUTH_SOCK='{}'; export SSH_AUTH_SOCK;", listen_path);
            println!("SSH_AGENT_PID='{}'; export SSH_AGENT_PID;", pid);
            println!("echo 'Agent pid {}';", pid);
            std::process::exit(0);
        }
        setsid();
        if let Ok(null_file) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
            use std::os::unix::io::AsRawFd;
            let fd = null_file.as_raw_fd();
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
        }
        let _ = std::env::set_current_dir("/");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Canonicalize md5 fingerprints
    let allowed_md5s: Vec<String> = cli.fingerprint.iter().map(|s| canonicalize_fingerprint(s)).collect();
    let confirmed_md5s: Vec<String> = cli.fingerprint_confirmed.iter().map(|s| canonicalize_fingerprint(s)).collect();

    // Setup upstream path
    #[cfg(windows)]
    let upstream_path = cli.in_pipe.clone().unwrap_or_else(|| {
        std::env::var("SSH_AUTH_SOCK")
            .unwrap_or_else(|_| r"\\.\pipe\openssh-ssh-agent".to_string())
    });

    #[cfg(unix)]
    let upstream_path = match cli.in_sock.clone() {
        Some(p) => p,
        None => match std::env::var("SSH_AUTH_SOCK") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Error: SSH_AUTH_SOCK environment variable must be set.");
                std::process::exit(1);
            }
        }
    };

    // Setup output (listening) path
    #[cfg(windows)]
    let listen_path = cli.out_pipe.unwrap_or_else(|| {
        r"\\.\pipe\openssh-ssh-agent-filtered".to_string()
    });

    #[cfg(unix)]
    let listen_path = cli.out_sock.unwrap_or_else(|| {
        format!("/tmp/agent.{}", std::process::id())
    });

    // Load and filter keys from upstream agent
    let (allowed_keys, confirmed_keys) = match setup_filters(
        &upstream_path,
        &cli.comment,
        &cli.comment_confirmed,
        &allowed_md5s,
        &confirmed_md5s,
        &cli.key,
        &cli.key_confirmed,
        cli.all_confirmed,
        cli.debug,
    ).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: Could not connect to the upstream SSH agent at '{}'.", upstream_path);
            #[cfg(windows)]
            eprintln!("Please make sure the 'OpenSSH Authentication Agent' (ssh-agent) service is running on Windows (e.g., run 'Start-Service ssh-agent' in administrator PowerShell).");
            #[cfg(unix)]
            eprintln!("Please check if your SSH_AUTH_SOCK is correct and the agent is running.");
            eprintln!("Underlying error details: {}", e);
            std::process::exit(1);
        }
    };

    // Daemonize if not debugging on Unix
    #[cfg(unix)]
    if !cli.debug {
        daemonize(&listen_path);
    }

    run_listener(
        &listen_path,
        upstream_path,
        allowed_keys,
        confirmed_keys,
        cli.all_confirmed,
        cli.name,
    ).await?;

    Ok(())
}
