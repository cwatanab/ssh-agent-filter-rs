# ssh-agent-filter-rust

Rust reimplementation of `ssh-agent-filter` with cross-platform support.

## Features

- **Windows Named Pipe Support**: Communicates natively with OpenSSH on Windows (defaults to `\\.\pipe\openssh-ssh-agent`).
- **Unix Domain Socket Support**: Fully compatible with Linux/macOS `SSH_AUTH_SOCK` socket files.
- **Native GUI Confirmation on Windows**: Prompts user using a native Win32 `MessageBox` GUI popup for key signatures.
- **SSH_ASKPASS on Unix**: Integrates with system askpass tools on Linux/macOS.

## Build

To compile the project, run:

```bash
cargo build --release
```

The compiled binaries will be located at:
- `target/release/ssh-agent-filter` (or `target/release/ssh-agent-filter.exe` on Windows)
- `target/release/afssh` (or `target/release/afssh.exe` on Windows)

## Usage

### Using afssh (on-demand wrapping)

You can run your `ssh` or `git` commands through `afssh` to automatically spawn the filter proxy, perform the connection, and clean up afterwards:

```powershell
# Windows Example
.\target\release\afssh.exe -c cwatana3@github.com-auth -- git clone git@github.com:user/repo.git
```

### Running ssh-agent-filter directly (persistent proxy)

#### Windows

1. Ensure your upstream `ssh-agent` service is running and has keys loaded.
2. Run the filter, specifying which keys to allow or require confirmation for:
   ```powershell
   .\target\release\ssh-agent-filter.exe -A
   ```
   This will run in the foreground and output env variables to export, e.g.:
   ```powershell
   Listening on Named Pipe: \\.\pipe\openssh-ssh-agent-filtered
   $env:SSH_AUTH_SOCK='\\.\pipe\openssh-ssh-agent-filtered'
   ```
3. Set your `SSH_AUTH_SOCK` environment variable in a new terminal or session:
   ```powershell
   $env:SSH_AUTH_SOCK='\\.\pipe\openssh-ssh-agent-filtered'
   ```
4. Now, any `ssh` connection will use the filtered agent. For keys not explicitly allowed, a Windows message box will pop up asking for confirmation.

#### Unix (Linux/macOS)

Run the filter:
```bash
./target/release/ssh-agent-filter -A
```
It will daemonize by default (unless `-d`/`--debug` is passed) and print the appropriate `export SSH_AUTH_SOCK="..."` command.
