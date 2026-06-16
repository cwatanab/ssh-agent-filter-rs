use std::path::PathBuf;

#[cfg(windows)]
fn configure_job_object(child_handle: std::os::windows::io::RawHandle) -> std::io::Result<()> {
    use std::ptr;
    use std::os::windows::io::RawHandle;

    unsafe extern "system" {
        fn CreateJobObjectW(lpJobAttributes: *mut std::ffi::c_void, lpName: *const u16) -> RawHandle;
        fn SetInformationJobObject(
            hJob: RawHandle,
            JobObjectInformationClass: u32,
            lpJobObjectInformation: *const std::ffi::c_void,
            cbJobObjectInformationLength: u32,
        ) -> i32;
        fn AssignProcessToJobObject(hJob: RawHandle, hProcess: RawHandle) -> i32;
        fn CloseHandle(hObject: RawHandle) -> i32;
    }

    unsafe {
        let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
        if job.is_null() || job as usize == !0 {
            return Err(std::io::Error::last_os_error());
        }

        #[repr(C)]
        struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            per_process_user_time_limit: i64,
            per_job_user_time_limit: i64,
            limit_flags: u32,
            minimum_working_set_size: usize,
            maximum_working_set_size: usize,
            active_process_limit: u32,
            affinity: usize,
            priority_class: u32,
            scheduling_class: u32,
        }

        #[repr(C)]
        struct IO_COUNTERS {
            read_operation_count: u64,
            write_operation_count: u64,
            other_operation_count: u64,
            read_transfer_count: u64,
            write_transfer_count: u64,
            other_transfer_count: u64,
        }

        #[repr(C)]
        struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
            io_info: IO_COUNTERS,
            process_memory_limit: usize,
            job_memory_limit: usize,
            peak_process_memory_limit: usize,
            peak_job_memory_limit: usize,
        }

        let mut info = std::mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        info.basic_limit_information.limit_flags = 0x00002000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        let res = SetInformationJobObject(
            job,
            9, // JobObjectExtendedLimitInformation
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        if res == 0 {
            CloseHandle(job);
            return Err(std::io::Error::last_os_error());
        }

        let res = AssignProcessToJobObject(job, child_handle);
        if res == 0 {
            CloseHandle(job);
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

fn print_usage() {
    println!("afssh -- Rust wrapper around ssh-agent-filter and ssh");
    println!("Usage:");
    println!("  afssh [ssh-agent-filter options] -- [ssh arguments]");
    println!();
    println!("Example:");
    println!("  afssh -c my-key-comment -- git clone git@github.com:user/repo.git");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Check for help or empty args
    if args.is_empty() || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_usage();
        std::process::exit(0);
    }

    // Split arguments at "--"
    let mut filter_args = Vec::new();
    let mut ssh_args = Vec::new();
    let mut found_dash = false;

    for arg in args {
        if arg == "--" {
            found_dash = true;
            continue;
        }
        if found_dash {
            ssh_args.push(arg);
        } else {
            filter_args.push(arg);
        }
    }

    if !found_dash {
        eprintln!("Error: '--' separator is required.");
        print_usage();
        std::process::exit(1);
    }

    // Determine unique listening path
    #[cfg(windows)]
    let listen_path = {
        let unique_id = format!(
            "afssh-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );
        PathBuf::from(format!(r"\\.\pipe\openssh-ssh-agent-{}", unique_id))
    };

    #[cfg(unix)]
    let temp_dir = {
        let dir = std::env::temp_dir().join(format!("afssh-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        dir
    };
    #[cfg(unix)]
    let listen_path = temp_dir.join("agent.sock");

    // Find ssh-agent-filter executable in the same directory as this binary
    let mut filter_exe = std::env::current_exe()?;
    filter_exe.set_file_name(if cfg!(windows) { "ssh-agent-filter.exe" } else { "ssh-agent-filter" });
    if !filter_exe.exists() {
        // Fallback to searching PATH
        filter_exe = PathBuf::from(if cfg!(windows) { "ssh-agent-filter.exe" } else { "ssh-agent-filter" });
    }

    let has_debug = filter_args.contains(&"-d".to_string()) || filter_args.contains(&"--debug".to_string());

    // Prepare arguments for ssh-agent-filter
    let mut child_args = filter_args;
    child_args.push("--debug".to_string()); // Run in foreground so we can manage its lifetime
    if cfg!(windows) {
        child_args.push("--out-pipe".to_string());
    } else {
        child_args.push("--out-sock".to_string());
    }
    child_args.push(listen_path.to_string_lossy().to_string());

    // Start ssh-agent-filter
    let mut filter_child = tokio::process::Command::new(&filter_exe)
        .args(&child_args)
        .stdout(std::process::Stdio::null())
        .stderr(if has_debug {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::piped()
        })
        .spawn()
        .map_err(|e| format!("Failed to start ssh-agent-filter ({:?}): {}", filter_exe, e))?;

    #[cfg(windows)]
    if let Some(handle) = filter_child.raw_handle() {
        let _ = configure_job_object(handle);
    }

    // Wait for ssh-agent-filter to start listening
    let mut ready = false;
    for _ in 0..100 {
        // Check if filter child exited early
        if let Some(status) = filter_child.try_wait()? {
            let mut err_msg = format!("ssh-agent-filter exited early with status: {}", status);
            if let Some(mut stderr) = filter_child.stderr.take() {
                let mut err_buf = Vec::new();
                if tokio::io::AsyncReadExt::read_to_end(&mut stderr, &mut err_buf).await.is_ok() {
                    if !err_buf.is_empty() {
                        err_msg.push_str(&format!("\nstderr:\n{}", String::from_utf8_lossy(&err_buf)));
                    }
                }
            }
            return Err(err_msg.into());
        }

        #[cfg(windows)]
        {
            // On Windows, try opening named pipe to check if it's listening
            if tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&listen_path)
                .is_ok()
            {
                ready = true;
                break;
            }
        }
        #[cfg(unix)]
        {
            if listen_path.exists() {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }

    if !ready {
        let _ = filter_child.kill().await;
        let mut err_msg = "ssh-agent-filter failed to start listening in time".to_string();
        if let Some(mut stderr) = filter_child.stderr.take() {
            let mut err_buf = Vec::new();
            if tokio::io::AsyncReadExt::read_to_end(&mut stderr, &mut err_buf).await.is_ok() {
                if !err_buf.is_empty() {
                    err_msg.push_str(&format!("\nstderr:\n{}", String::from_utf8_lossy(&err_buf)));
                }
            }
        }
        return Err(err_msg.into());
    }

    // Spawn ssh process with SSH_AUTH_SOCK pointed to the filtered socket/pipe
    let mut ssh_child = match tokio::process::Command::new("ssh")
        .arg("-A")
        .args(&ssh_args)
        .env("SSH_AUTH_SOCK", &listen_path)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = filter_child.kill().await;
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(&listen_path);
                let _ = std::fs::remove_dir_all(&temp_dir);
            }
            return Err(format!("Failed to spawn ssh command: {}", e).into());
        }
    };

    // Wait for ssh to complete
    let exit_status = match ssh_child.wait().await {
        Ok(status) => status,
        Err(e) => {
            let _ = filter_child.kill().await;
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(&listen_path);
                let _ = std::fs::remove_dir_all(&temp_dir);
            }
            return Err(e.into());
        }
    };

    // Clean up ssh-agent-filter
    let _ = filter_child.kill().await;

    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&listen_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = exit_status.code() {
            std::process::exit(code);
        } else if let Some(signal) = exit_status.signal() {
            std::process::exit(128 + signal);
        } else {
            std::process::exit(1);
        }
    }
    #[cfg(windows)]
    {
        std::process::exit(exit_status.code().unwrap_or(0));
    }
}
