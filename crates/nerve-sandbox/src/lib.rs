//! Confinement for the commands a node runs (docs/dev/policy-engine.md).
//!
//! The sandbox confines with Landlock on Linux, in `folders` mode: a command reads
//! the system directories and the folders flagged `r`, writes only the `w`
//! folders, and runs programs only from the system directories and the `x`
//! folders. The rules are applied in a small shim, `nerve-node __exec-shim`,
//! which the node starts per command: Landlock restricts the calling process,
//! and doing that between `fork` and `exec` of a multi-threaded async node is
//! not safe, while the shim is single-threaded.
//!
//! On Windows a `folders` command runs in an AppContainer, one per center
//! ([`appcontainer`]): a process there opens only what carries a grant for the
//! container's SID, and what Windows opens to every AppContainer (the system
//! folders and Program Files, for reading and running). The node puts grants
//! on the center's folders for their flags ([`acl`]) and takes them off when a
//! folder goes. The shim starts the command in the container and waits for it.
//!
//! Everything else in this area is a stub (see [`stubs`]).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The argument that selects the shim in the `nerve-node` binary. Hidden from
/// `--help`.
pub const SHIM_ARG: &str = "__exec-shim";

/// What a confined command may touch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockSpec {
    pub read: Vec<PathBuf>,
    /// Writable, and nothing more: a folder that is also to be read is in
    /// `read` as well.
    pub write: Vec<PathBuf>,
    /// Programs below these may run. The files there can be read by name too
    /// (see `landlock_rules::prepare`), the folders not listed.
    pub exec: Vec<PathBuf>,
}

/// What the node sends the shim on its stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShimSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The node's pid: a shim whose parent already changed exits at once.
    pub parent: u32,
    #[serde(default)]
    pub landlock: Option<LandlockSpec>,
    /// Windows: run the command in this AppContainer.
    #[serde(default)]
    pub container: Option<ContainerSpec>,
}

/// What a PowerShell command in an AppContainer starts with. PowerShell
/// checks every folder above its working folder when it takes that as its
/// location, and the container may not look at them (`C:\`, `C:\Users`),
/// so it would stand somewhere else and start programs there. A drive
/// `Work:` rooted at the working folder puts it where it belongs; paths
/// below it work, relative or under `Work:\`, and so do whole paths to
/// files.
pub const POWERSHELL_START: &str = "$null = New-PSDrive -Name Work -PSProvider FileSystem \
     -Root ([Environment]::CurrentDirectory) -Scope Global -ErrorAction Stop; \
     Set-Location Work:\\ -ErrorAction Stop; ";

/// The AppContainer a Windows command runs in. Its SID is derived from the
/// name, so the node's grants and the shim's process agree on it without a
/// profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSpec {
    pub name: String,
}

/// The largest spec the shim reads.
const MAX_SPEC: u64 = 1 << 20;

/// Exit code of a shim that could not set up the command.
pub const SHIM_FAILED: i32 = 126;

/// Runs the shim: reads its [`ShimSpec`] (JSON) from stdin up to its end,
/// confines itself, and replaces itself with the command, whose stdin is then
/// `/dev/null`. Returns only on failure, with the exit code to use. Must run
/// before any thread starts in the process.
///
/// The spec comes on stdin rather than in argv so it does not show in
/// `/proc/<pid>/cmdline`.
pub fn shim_main() -> i32 {
    use std::io::Read;
    let mut json = Vec::new();
    if std::io::stdin()
        .lock()
        .take(MAX_SPEC)
        .read_to_end(&mut json)
        .is_err()
    {
        eprintln!("nerve-node: the exec shim got no spec");
        return SHIM_FAILED;
    }
    match serde_json::from_slice::<ShimSpec>(&json) {
        Ok(spec) => imp::run(spec),
        Err(e) => {
            eprintln!("nerve-node: bad exec shim spec: {e}");
            SHIM_FAILED
        }
    }
}

/// How this machine can confine commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confinement {
    /// The kernel's Landlock ABI version; `None` when Landlock is missing or
    /// off.
    pub landlock_abi: Option<i32>,
    /// Windows: commands run in an AppContainer. Every Windows the node
    /// runs on (10 and later) has them.
    pub appcontainer: bool,
}

impl Confinement {
    pub fn detect() -> Confinement {
        Confinement {
            landlock_abi: landlock_abi(),
            appcontainer: cfg!(windows),
        }
    }

    /// Whether `folders` mode can confine commands.
    pub fn available(&self) -> bool {
        self.landlock_abi.is_some() || self.appcontainer
    }

    /// The `confinement` string of the `exec` state.
    pub fn describe(&self) -> String {
        match self.landlock_abi {
            Some(v) => format!("landlock v{v}"),
            None if self.appcontainer => "appcontainer".into(),
            None => "none".into(),
        }
    }
}

/// Directories every confined command may read and run programs from.
pub fn system_dirs() -> Vec<PathBuf> {
    [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib32",
        "/lib64",
        "/etc",
        "/opt",
        "/nix/store",
        "/proc",
        "/sys",
        "/dev",
        "/run",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect()
}

/// Files every confined command may write: the null and terminal devices,
/// nothing else outside its folders.
pub fn system_writable() -> Vec<PathBuf> {
    ["/dev/null", "/dev/zero", "/dev/tty", "/dev/full"]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

#[cfg(target_os = "linux")]
fn landlock_abi() -> Option<i32> {
    landlock_rules::abi_version()
}

#[cfg(not(target_os = "linux"))]
fn landlock_abi() -> Option<i32> {
    None
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{SHIM_FAILED, ShimSpec};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    pub fn run(spec: ShimSpec) -> i32 {
        // SAFETY: prctl and getppid with plain integer arguments.
        unsafe {
            // The command dies with the node instead of running on unseen.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            if libc::getppid() as u32 != spec.parent {
                return SHIM_FAILED;
            }
        }
        if spec.container.is_some() {
            eprintln!("nerve-node: AppContainers are Windows'");
            return SHIM_FAILED;
        }
        if let Some(l) = &spec.landlock {
            let applied = super::landlock_rules::prepare(l)
                .and_then(|r| super::landlock_rules::enforce(r).map_err(|e| e.to_string()));
            if let Err(e) = applied {
                eprintln!("nerve-node: cannot confine the command: {e}");
                return SHIM_FAILED;
            }
        }
        let e = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .exec();
        eprintln!("nerve-node: cannot start {}: {e}", spec.program.display());
        127
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod imp {
    use super::{SHIM_FAILED, ShimSpec};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    pub fn run(spec: ShimSpec) -> i32 {
        if spec.landlock.is_some() || spec.container.is_some() {
            eprintln!("nerve-node: no Landlock on this system");
            return SHIM_FAILED;
        }
        let e = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .exec();
        eprintln!("nerve-node: cannot start {}: {e}", spec.program.display());
        127
    }
}

#[cfg(windows)]
mod imp {
    use super::{SHIM_FAILED, ShimSpec};
    use std::process::{Command, Stdio};

    pub fn run(spec: ShimSpec) -> i32 {
        if spec.landlock.is_some() {
            return SHIM_FAILED;
        }
        // The node runs the shim in a job object of the command's own, which
        // holds this process and what it starts, the container's processes
        // too.
        if let Some(c) = &spec.container {
            return match super::appcontainer::run(&spec.program, &spec.args, &c.name) {
                Ok(code) => code as i32,
                Err(e) => {
                    eprintln!(
                        "nerve-node: cannot start {} in its AppContainer: {e}",
                        spec.program.display()
                    );
                    SHIM_FAILED
                }
            };
        }
        match Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .status()
        {
            Ok(st) => st.code().unwrap_or(255),
            Err(e) => {
                eprintln!("nerve-node: cannot start {}: {e}", spec.program.display());
                127
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub mod landlock_rules {
    //! Landlock rules for a `folders` command. Every filesystem access is
    //! handled (so denied unless a rule allows it). Where the kernel supports
    //! it, the command also cannot signal processes outside its sandbox or
    //! reach abstract sockets.

    use super::LandlockSpec;
    use landlock::{
        ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
        RulesetStatus, Scope, path_beneath_rules,
    };

    /// Best effort up to this ABI: older kernels enforce what they know.
    const ABI_WANTED: ABI = ABI::V6;

    pub fn prepare(spec: &LandlockSpec) -> Result<RulesetCreated, String> {
        let e = |e: landlock::RulesetError| e.to_string();
        // Running a program is its own right, granted only where `exec` says.
        // The kernel opens a program for reading as well as for execution, so
        // Landlock refuses the exec of a file it may not read: an `exec`
        // folder therefore also lets a command read the files in it by name.
        // It cannot list the folder (no ReadDir), and `read` stays the set
        // that grants whole trees.
        let mut read = AccessFs::from_read(ABI_WANTED);
        read.remove(AccessFs::Execute);
        // Only the write rights, so a folder that may be written but not read
        // (`w` without `r`) stays unreadable; reading is the `read` set's.
        let write = AccessFs::from_write(ABI_WANTED);
        let mut rs = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI_WANTED))
            .map_err(e)?;
        if !Scope::from_all(ABI_WANTED).is_empty() {
            rs = rs.scope(Scope::from_all(ABI_WANTED)).map_err(e)?;
        }
        rs.create()
            .map_err(e)?
            .add_rules(path_beneath_rules(&spec.read, read))
            .map_err(e)?
            .add_rules(path_beneath_rules(&spec.write, write))
            .map_err(e)?
            .add_rules(path_beneath_rules(
                &spec.exec,
                AccessFs::Execute | AccessFs::ReadFile,
            ))
            .map_err(e)
    }

    /// Restricts the calling process and what it runs. Fails (so the command
    /// does not run) when the kernel enforces nothing.
    pub fn enforce(rs: RulesetCreated) -> std::io::Result<()> {
        let st = rs.restrict_self().map_err(std::io::Error::other)?;
        if st.ruleset == RulesetStatus::NotEnforced {
            return Err(std::io::Error::other("Landlock is not enforced"));
        }
        Ok(())
    }

    /// The kernel's Landlock ABI version, `None` when Landlock is off or
    /// missing.
    pub fn abi_version() -> Option<i32> {
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        // SAFETY: the version query takes no ruleset and returns an integer.
        let v = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        (v > 0).then_some(v as i32)
    }
}

pub mod acl {
    //! The rights a folder's flags give a Windows AppContainer, as the access
    //! masks of the grants on the folder: one for the folder and the folders
    //! below it, one for the files below it. Plain values, so they are
    //! tested on every platform.
    //!
    //! The flags stay independent, as on Linux: `w` gives no read and no
    //! listing, and `x` runs and reads files by name but lists nothing (a
    //! program cannot run from a file it may not read, and a script is read
    //! by its interpreter). No flag gives a right on the access list or the
    //! owner, so a command cannot widen its own grants.

    pub const READ_DATA: u32 = 0x1; // FILE_LIST_DIRECTORY on a folder
    pub const WRITE_DATA: u32 = 0x2; // FILE_ADD_FILE
    pub const APPEND_DATA: u32 = 0x4; // FILE_ADD_SUBDIRECTORY
    pub const READ_EA: u32 = 0x8;
    pub const WRITE_EA: u32 = 0x10;
    pub const EXECUTE: u32 = 0x20; // FILE_TRAVERSE
    pub const DELETE_CHILD: u32 = 0x40;
    pub const READ_ATTRIBUTES: u32 = 0x80;
    pub const WRITE_ATTRIBUTES: u32 = 0x100;
    pub const DELETE: u32 = 0x1_0000;
    pub const READ_CONTROL: u32 = 0x2_0000;
    pub const WRITE_DAC: u32 = 0x4_0000;
    pub const WRITE_OWNER: u32 = 0x8_0000;
    pub const SYNCHRONIZE: u32 = 0x10_0000;

    /// What every flag gives: waiting on a handle and reading the
    /// attributes and the access list, as `stat` does on Linux.
    const BASE: u32 = SYNCHRONIZE | READ_ATTRIBUTES | READ_CONTROL;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Masks {
        /// The folder itself and every folder below it.
        pub dir: u32,
        /// Every file below it (or the path itself, when it is a file).
        pub file: u32,
    }

    /// The masks for a folder with these flags; both 0 without a flag.
    pub fn masks(read: bool, write: bool, execute: bool) -> Masks {
        let mut m = Masks::default();
        if read {
            m.dir |= BASE | READ_DATA | READ_EA | EXECUTE;
            m.file |= BASE | READ_DATA | READ_EA;
        }
        if write {
            m.dir |= BASE
                | WRITE_DATA
                | APPEND_DATA
                | WRITE_EA
                | WRITE_ATTRIBUTES
                | DELETE_CHILD
                | DELETE;
            m.file |= BASE | WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES | DELETE;
        }
        if execute {
            m.dir |= BASE | EXECUTE;
            // FILE_GENERIC_READ, as a script's interpreter opens it.
            m.file |= BASE | EXECUTE | READ_DATA | READ_EA;
        }
        m
    }

    /// The command line that hands `args` to `program` so that it reads
    /// them back as they are (`CommandLineToArgvW`'s rules, as Rust's own
    /// `Command` writes it on Windows): an argument with a space or a tab, or
    /// an empty one, goes in quotes, a quote in it gets a backslash, and the
    /// backslashes before a quote are doubled. The program is always quoted.
    pub fn command_line(program: &str, args: &[String]) -> String {
        let mut out = format!("\"{program}\"");
        for a in args {
            out.push(' ');
            let quote = a.is_empty() || a.contains([' ', '\t']);
            if quote {
                out.push('"');
            }
            let mut backslashes = 0;
            for c in a.chars() {
                if c == '\\' {
                    backslashes += 1;
                } else {
                    if c == '"' {
                        out.extend(std::iter::repeat_n('\\', backslashes + 1));
                    }
                    backslashes = 0;
                }
                out.push(c);
            }
            if quote {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push('"');
            }
        }
        out
    }
}

#[cfg(windows)]
pub mod appcontainer {
    //! The AppContainer of a Windows `folders` command: the grants on its
    //! folders ([`set`]) and the process in it ([`run`]).
    //!
    //! The container's SID is derived from its name, so the node puts grants
    //! on folders for it without asking anything of Windows. To start a
    //! process in it, Windows wants its profile; the shim makes that for the
    //! user it runs as ([`ensure_profile`]), and the node removes it with the
    //! container's last grant ([`remove_profile`]). The container has the
    //! network (`internetClient`, `internetClientServer`,
    //! `privateNetworkClientServer`), which Landlock leaves open too, but not
    //! the machine's own loopback address, which Windows keeps from every
    //! AppContainer.

    use std::ffi::{OsStr, c_void};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_ALL, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
        DeriveAppContainerSidFromAppContainerName,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION,
        AclSizeInformation, AddAccessAllowedAceEx, AddAce, CONTAINER_INHERIT_ACE,
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, FreeSid, GetAce,
        GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
        INHERIT_ONLY_ACE, INHERITED_ACE, InitializeAcl, OBJECT_INHERIT_ACE,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser, UNPROTECTED_DACL_SECURITY_INFORMATION, WinCapabilityInternetClientServerSid,
        WinCapabilityInternetClientSid, WinCapabilityPrivateNetworkClientServerSid,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        GetCurrentProcess, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::acl::{Masks, command_line};

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const SE_GROUP_ENABLED: u32 = 4;

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn check(ok: i32) -> io::Result<()> {
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// The SID of the container `name`.
    pub struct Sid(PSID);

    impl Sid {
        pub fn derive(name: &str) -> io::Result<Sid> {
            let n = wide(OsStr::new(name));
            let mut sid: PSID = null_mut();
            // SAFETY: a NUL-terminated name; the call sets `sid` to a SID it
            // allocated, freed with FreeSid.
            let hr = unsafe { DeriveAppContainerSidFromAppContainerName(n.as_ptr(), &mut sid) };
            if hr < 0 || sid.is_null() {
                return Err(io::Error::other(format!(
                    "cannot derive the AppContainer SID of {name} ({hr:#x})"
                )));
            }
            Ok(Sid(sid))
        }
    }

    impl Drop for Sid {
        fn drop(&mut self) {
            // SAFETY: the SID came from DeriveAppContainerSidFromAppContainerName.
            unsafe { FreeSid(self.0) };
        }
    }

    /// Memory Windows allocated with LocalAlloc, freed when dropped.
    struct Local(*mut c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: the pointer came from LocalAlloc (or is null).
            unsafe { LocalFree(self.0) };
        }
    }

    /// Puts the grants of `masks` for the container `name` on `path`, in
    /// place of any it had (`None` takes them off). They are inherited by
    /// everything below `path`, and Windows passes the change on to what is
    /// there now. Other entries of the access list stay as they are.
    pub fn set(path: &Path, name: &str, masks: Option<Masks>) -> io::Result<()> {
        let sid = Sid::derive(name)?;
        let is_dir = std::fs::metadata(path)?.is_dir();
        let wpath = wide(path.as_os_str());
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated path and out pointers to locals; the
        // descriptor is freed with LocalFree, and `dacl` points into it.
        let e = unsafe {
            GetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let _sd = Local(sd);
        if dacl.is_null() {
            return Err(io::Error::other(
                "it has no access list, so everyone may open it; the node does not give it one",
            ));
        }
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: the descriptor is valid while `_sd` lives.
        check(unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) })?;
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: a valid ACL and a buffer of the size given.
        check(unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        })?;
        // SAFETY: a valid SID.
        let sid_len = unsafe { GetLengthSid(sid.0) };
        let ace_len = size_of::<ACCESS_ALLOWED_ACE>() as u32 - 4 + sid_len;
        let size = info.AclBytesInUse + 2 * ace_len;
        // u32s, since an ACL is aligned to them.
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let new = buf.as_mut_ptr() as *mut ACL;
        // SAFETY: the buffer holds `size` bytes.
        check(unsafe { InitializeAcl(new, size, ACL_REVISION_DS) })?;
        for i in 0..info.AceCount {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: `i` is below the ACE count; the ACE lies in `dacl`.
            check(unsafe { GetAce(dacl, i, &mut ace) })?;
            // SAFETY: every ACE starts with its header.
            let h = unsafe { &*(ace as *const ACE_HEADER) };
            // Inherited entries are Windows' to set: it derives them from
            // the parent again when the list is written.
            if u32::from(h.AceFlags) & INHERITED_ACE != 0 {
                continue;
            }
            let plain = matches!(h.AceType, ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE);
            // SAFETY: an allowed or denied ACE has its SID at SidStart.
            let ours = plain
                && unsafe {
                    let a = ace as *const ACCESS_ALLOWED_ACE;
                    EqualSid(&raw const (*a).SidStart as PSID, sid.0) != 0
                };
            if ours {
                continue;
            }
            // SAFETY: the ACE and its size come from the old list, and the
            // new one has room for all of them.
            check(unsafe { AddAce(new, ACL_REVISION_DS, u32::MAX, ace, u32::from(h.AceSize)) })?;
        }
        if let Some(m) = masks {
            let add = |flags: u32, mask: u32| {
                if mask == 0 {
                    return Ok(());
                }
                // SAFETY: the list has room for two more of these ACEs.
                check(unsafe { AddAccessAllowedAceEx(new, ACL_REVISION_DS, flags, mask, sid.0) })
            };
            if is_dir {
                add(CONTAINER_INHERIT_ACE, m.dir)?;
                add(OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE, m.file)?;
            } else {
                add(0, m.file)?;
            }
        }
        // A list that did not inherit keeps not inheriting.
        let keep = if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        // SAFETY: a NUL-terminated path and a valid ACL.
        let e = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | keep,
                null_mut(),
                null_mut(),
                new,
                null(),
            )
        };
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        Ok(())
    }

    /// HRESULTs of the profile calls.
    const ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;
    const NOT_FOUND: [i32; 2] = [0x8007_0002_u32 as i32, 0x8007_0490_u32 as i32];

    /// Makes the profile of the container `name` for the user this process
    /// runs as, unless it has one: Windows starts no process in a container
    /// without one. It is a registry key and a folder below
    /// `%LOCALAPPDATA%\Packages`, which only the container and the user
    /// reach; [`remove_profile`] takes it away.
    fn ensure_profile(name: &str) -> io::Result<()> {
        let n = wide(OsStr::new(name));
        let mut sid: PSID = null_mut();
        // SAFETY: NUL-terminated strings, no capabilities, and an out
        // pointer the call fills with a SID it allocated.
        let hr = unsafe {
            CreateAppContainerProfile(n.as_ptr(), n.as_ptr(), n.as_ptr(), null(), 0, &mut sid)
        };
        if !sid.is_null() {
            // SAFETY: the SID came from CreateAppContainerProfile.
            unsafe { FreeSid(sid) };
        }
        if hr < 0 && hr != ALREADY_EXISTS {
            return Err(io::Error::other(format!(
                "cannot make the AppContainer profile {name} ({hr:#x})"
            )));
        }
        Ok(())
    }

    /// Takes the profile of the container `name` away from the user this
    /// process runs as; one that is not there is fine.
    pub fn remove_profile(name: &str) -> io::Result<()> {
        let n = wide(OsStr::new(name));
        // SAFETY: a NUL-terminated name.
        let hr = unsafe { DeleteAppContainerProfile(n.as_ptr()) };
        if hr < 0 && !NOT_FOUND.contains(&hr) {
            return Err(io::Error::other(format!(
                "cannot remove the AppContainer profile {name} ({hr:#x})"
            )));
        }
        Ok(())
    }

    /// A capability SID in a buffer of its own.
    fn capability(kind: i32) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 68]; // SECURITY_MAX_SID_SIZE
        let mut len = buf.len() as u32;
        // SAFETY: a buffer of `len` bytes for the SID.
        check(unsafe { CreateWellKnownSid(kind, null_mut(), buf.as_mut_ptr() as PSID, &mut len) })?;
        Ok(buf)
    }

    /// `program` as CreateProcessW takes it: a full path. A bare name is
    /// looked for on `PATH`, with `.exe` when it has no extension.
    fn find(program: &Path) -> io::Result<PathBuf> {
        if program.components().count() > 1 {
            return Ok(program.to_path_buf());
        }
        let name = if program.extension().is_some() {
            program.to_path_buf()
        } else {
            program.with_extension("exe")
        };
        std::env::var_os("PATH")
            .iter()
            .flat_map(std::env::split_paths)
            .map(|d| d.join(&name))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} is not on PATH", name.display()),
                )
            })
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn CreateWindowStationW(
            name: *const u16,
            flags: u32,
            access: u32,
            sa: *const SECURITY_ATTRIBUTES,
        ) -> HANDLE;
        fn GetProcessWindowStation() -> HANDLE;
        fn SetProcessWindowStation(station: HANDLE) -> i32;
        fn CreateDesktopW(
            name: *const u16,
            device: *const u16,
            mode: *const c_void,
            flags: u32,
            access: u32,
            sa: *const SECURITY_ATTRIBUTES,
        ) -> HANDLE;
        fn CloseDesktop(desktop: HANDLE) -> i32;
        fn CloseWindowStation(station: HANDLE) -> i32;
    }

    /// The SID as text (`S-1-...`).
    fn sid_text(sid: PSID) -> io::Result<String> {
        let mut text: *mut u16 = null_mut();
        // SAFETY: a valid SID; the call allocates the string, freed below.
        check(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
        let _text = Local(text as *mut c_void);
        // SAFETY: a NUL-terminated wide string.
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let wide = unsafe { std::slice::from_raw_parts(text, len) };
        Ok(String::from_utf16_lossy(wide))
    }

    /// This process's token, closed when dropped.
    struct Token(HANDLE);

    impl Token {
        fn open() -> io::Result<Token> {
            let mut token: HANDLE = null_mut();
            // SAFETY: this process's pseudo handle and an out pointer.
            check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
            Ok(Token(token))
        }
    }

    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: opened in `open`, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// The SID of the user this process runs as, as text.
    fn user_sid() -> io::Result<String> {
        let token = Token::open()?;
        let mut len = 0u32;
        // SAFETY: the first call asks for the size only.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut len) };
        let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
        // SAFETY: a buffer of at least `len` bytes, aligned for TOKEN_USER.
        check(unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr() as *mut c_void,
                len,
                &mut len,
            )
        })?;
        // SAFETY: the call filled a TOKEN_USER, whose SID lies in `buf`.
        sid_text(unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid })
    }

    /// A window station with one desktop, of the command's own. Windows
    /// keeps an AppContainer out of the window station and desktop it was
    /// started from (a service's, or the user's), and a program that loads
    /// the user interface library (PowerShell does) does not start without
    /// one. Only this user and the container may open these, so the command
    /// does not reach the user's windows or clipboard either. They go when
    /// the shim does.
    struct Desktop {
        station: HANDLE,
        desktop: HANDLE,
        /// `station\desktop`, for the startup info.
        name: Vec<u16>,
    }

    impl Drop for Desktop {
        fn drop(&mut self) {
            // SAFETY: made in `desktop`, closed once.
            unsafe {
                CloseDesktop(self.desktop);
                CloseWindowStation(self.station);
            }
        }
    }

    fn desktop(container: &Sid) -> io::Result<Desktop> {
        let sddl = format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;{})(A;;GA;;;{})",
            user_sid()?,
            sid_text(container.0)?
        );
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed
        // with LocalFree.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(&sddl)).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        })?;
        let _sd = Local(sd);
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let name = format!("nerve-{}", std::process::id());
        // SAFETY: NUL-terminated names and security attributes that live
        // for the calls; the handles are closed by `Desktop`.
        unsafe {
            let station =
                CreateWindowStationW(wide(OsStr::new(&name)).as_ptr(), 0, GENERIC_ALL, &sa);
            if station.is_null() {
                return Err(io::Error::last_os_error());
            }
            // CreateDesktopW makes the desktop in this process's window
            // station, so this process stands in the new one meanwhile.
            let old = GetProcessWindowStation();
            if SetProcessWindowStation(station) == 0 {
                let e = io::Error::last_os_error();
                CloseWindowStation(station);
                return Err(e);
            }
            let desktop = CreateDesktopW(
                wide(OsStr::new("Default")).as_ptr(),
                null(),
                null(),
                0,
                GENERIC_ALL,
                &sa,
            );
            let made = io::Error::last_os_error();
            SetProcessWindowStation(old);
            if desktop.is_null() {
                CloseWindowStation(station);
                return Err(made);
            }
            Ok(Desktop {
                station,
                desktop,
                name: wide(OsStr::new(&format!("{name}\\Default"))),
            })
        }
    }

    /// Makes `h` inheritable, for the child's standard handles.
    fn inheritable(h: HANDLE) -> io::Result<()> {
        // SAFETY: a handle this process holds.
        check(unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) })
    }

    /// Runs `program` with `args` in the container `name`, with this
    /// process's environment, working folder, stdout and stderr, and the
    /// null device as its stdin; no other handle goes to it. Waits for it
    /// and returns its exit code.
    pub fn run(program: &Path, args: &[String], name: &str) -> io::Result<u32> {
        ensure_profile(name)?;
        let sid = Sid::derive(name)?;
        let mut caps_buf = [
            WinCapabilityInternetClientSid,
            WinCapabilityInternetClientServerSid,
            WinCapabilityPrivateNetworkClientServerSid,
        ]
        .map(capability);
        let mut caps = Vec::new();
        for c in caps_buf.iter_mut() {
            let c = c
                .as_mut()
                .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
            caps.push(SID_AND_ATTRIBUTES {
                Sid: c.as_mut_ptr() as PSID,
                Attributes: SE_GROUP_ENABLED,
            });
        }
        let sc = SECURITY_CAPABILITIES {
            AppContainerSid: sid.0,
            Capabilities: caps.as_mut_ptr(),
            CapabilityCount: caps.len() as u32,
            Reserved: 0,
        };
        let null_in = std::fs::File::open("NUL")
            .map_err(|e| io::Error::new(e.kind(), format!("the null device: {e}")))?;
        let stdin = null_in.as_raw_handle() as HANDLE;
        let stdout = std::io::stdout().as_raw_handle() as HANDLE;
        let stderr = std::io::stderr().as_raw_handle() as HANDLE;
        let mut handles = vec![stdin];
        for h in [stdout, stderr] {
            if !h.is_null() && !handles.contains(&h) {
                handles.push(h);
            }
        }
        for h in &handles {
            inheritable(*h)?;
        }

        let mut size = 0usize;
        // SAFETY: the first call only asks for the size and fails with
        // ERROR_INSUFFICIENT_BUFFER.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size) };
        let mut attrs = vec![0usize; size.div_ceil(size_of::<usize>())];
        let list = attrs.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        // SAFETY: a buffer of at least `size` bytes.
        check(unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) })?;
        struct List(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for List {
            fn drop(&mut self) {
                // SAFETY: initialised above, deleted once.
                unsafe { DeleteProcThreadAttributeList(self.0) };
            }
        }
        let _list = List(list);
        // SAFETY: the values outlive the list, which is used only below.
        unsafe {
            check(UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                &sc as *const _ as *const c_void,
                size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            ))?;
            check(UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *const c_void,
                handles.len() * size_of::<HANDLE>(),
                null_mut(),
                null(),
            ))?;
        }
        let mut desk = desktop(&sid)
            .map_err(|e| io::Error::new(e.kind(), format!("a desktop of its own: {e}")))?;
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.lpDesktop = desk.name.as_mut_ptr();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = stdin;
        si.StartupInfo.hStdOutput = stdout;
        si.StartupInfo.hStdError = stderr;
        si.lpAttributeList = list;
        let exe = find(program)?;
        let app = wide(exe.as_os_str());
        let mut line = wide(OsStr::new(&command_line(&exe.to_string_lossy(), args)));
        let mut pi = PROCESS_INFORMATION::default();
        let started = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", exe.display()));
        // SAFETY: NUL-terminated strings, a writable command line, and the
        // startup info with its attribute list, all alive for the call.
        check(unsafe {
            CreateProcessW(
                app.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT,
                null(),
                null(),
                &si.StartupInfo,
                &mut pi,
            )
        })
        .map_err(started)?;
        let mut code = 0u32;
        // SAFETY: handles CreateProcessW returned, each closed once.
        unsafe {
            CloseHandle(pi.hThread);
            WaitForSingleObject(pi.hProcess, INFINITE);
            let ok = GetExitCodeProcess(pi.hProcess, &mut code);
            CloseHandle(pi.hProcess);
            check(ok)?;
        }
        Ok(code)
    }
}

/// What the sandbox does not do. Each returns an error ending in
/// [`stubs::NOT_DONE`], so callers and the CLI say so plainly instead of
/// pretending.
pub mod stubs {
    pub const NOT_DONE: &str = "not done";

    /// A cgroup per command (memory, process count, kill of the whole tree).
    pub fn cgroup() -> Result<(), String> {
        Err(format!("cgroup confinement: {NOT_DONE}"))
    }

    /// Running commands as a dedicated, unprivileged user.
    pub fn dedicated_user() -> Result<(), String> {
        Err(format!("dedicated user: {NOT_DONE}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_say_not_done() {
        for r in [stubs::cgroup(), stubs::dedicated_user()] {
            assert!(r.unwrap_err().ends_with(stubs::NOT_DONE));
        }
    }

    #[test]
    fn spec_round_trips_strictly() {
        let s = ShimSpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "true".into()],
            parent: 1,
            landlock: Some(LandlockSpec::default()),
            container: Some(ContainerSpec {
                name: "nerve.x".into(),
            }),
        };
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<ShimSpec>(&j).unwrap(), s);
        let extra = r#"{"program":"x","args":[],"parent":1,"x":1}"#;
        assert!(serde_json::from_str::<ShimSpec>(extra).is_err());
        let plain = r#"{"program":"x","args":[],"parent":1}"#;
        let plain = serde_json::from_str::<ShimSpec>(plain).unwrap();
        assert_eq!((plain.landlock, plain.container), (None, None));
        let mut c = Confinement {
            landlock_abi: None,
            appcontainer: false,
        };
        assert_eq!(c.describe(), "none");
        assert!(!c.available());
        c.appcontainer = true;
        assert_eq!(c.describe(), "appcontainer");
        assert!(c.available());
        assert_eq!(Confinement::detect().appcontainer, cfg!(windows));
    }

    /// Each flag gives its own rights and nothing of another's: `w` reads
    /// and lists nothing, `x` runs and reads files but lists nothing, and
    /// no flag may change the access list or the owner.
    #[test]
    fn each_flag_gives_its_own_windows_rights() {
        use acl::*;
        let none = masks(false, false, false);
        assert_eq!(none, Masks::default());
        let r = masks(true, false, false);
        assert_eq!(r.dir & READ_DATA, READ_DATA, "r lists a folder");
        assert_eq!(r.file & READ_DATA, READ_DATA, "r reads a file");
        assert_eq!(r.file & EXECUTE, 0, "r runs nothing");
        assert_eq!((r.dir | r.file) & (WRITE_DATA | APPEND_DATA | DELETE), 0);
        let w = masks(false, true, false);
        assert_eq!(w.dir & (WRITE_DATA | APPEND_DATA), WRITE_DATA | APPEND_DATA);
        assert_eq!(w.file & WRITE_DATA, WRITE_DATA);
        assert_eq!(
            (w.dir | w.file) & (READ_DATA | EXECUTE),
            0,
            "w reads nothing"
        );
        let x = masks(false, false, true);
        assert_eq!(x.file & (EXECUTE | READ_DATA), EXECUTE | READ_DATA);
        assert_eq!(x.dir & READ_DATA, 0, "x lists no folder");
        assert_eq!((x.dir | x.file) & (WRITE_DATA | DELETE), 0);
        let all = masks(true, true, true);
        assert_eq!((all.dir | all.file) & (WRITE_DAC | WRITE_OWNER), 0);
        assert_eq!(all.dir, r.dir | w.dir | x.dir);
        assert_eq!(all.file, r.file | w.file | x.file);
    }

    /// The command line reads back as the arguments given, by the rules of
    /// `CommandLineToArgvW`.
    #[test]
    fn windows_command_lines_quote_as_rust_does() {
        let line = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            acl::command_line(r"C:\Windows\cmd.exe", &args)
        };
        assert_eq!(line(&["/C", "dir"]), r#""C:\Windows\cmd.exe" /C dir"#);
        assert_eq!(
            line(&["-Command", "echo 'a b'"]),
            r#""C:\Windows\cmd.exe" -Command "echo 'a b'""#
        );
        assert_eq!(line(&[""]), r#""C:\Windows\cmd.exe" """#);
        assert_eq!(
            line(&[r#"say "hi""#]),
            r#""C:\Windows\cmd.exe" "say \"hi\"""#
        );
        assert_eq!(line(&[r"a\b c\"]), r#""C:\Windows\cmd.exe" "a\b c\\""#);
        assert_eq!(line(&[r#"a\"b"#]), r#""C:\Windows\cmd.exe" a\\\"b"#);
    }

    /// Runs `command` in cmd in the container `name`, in `cwd`; its exit
    /// code.
    #[cfg(windows)]
    fn in_container(name: &str, cwd: &std::path::Path, command: &str) -> u32 {
        run_in_container(name, cwd, "cmd.exe", &["/C", command]).0
    }

    /// Runs `program` with `args` in the container `name`, in `cwd`; its
    /// exit code and its output.
    #[cfg(windows)]
    fn run_in_container(
        name: &str,
        cwd: &std::path::Path,
        program: &str,
        args: &[&str],
    ) -> (u32, String) {
        // The shim's process runs in the command's folder; so does this one
        // for the call. Tests run in threads, so a child process takes the
        // place of the shim.
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "tests::helper_runs_in_a_container",
                "--ignored",
                "--nocapture",
            ])
            .env("NERVE_TEST_CONTAINER", name)
            .env("NERVE_TEST_PROGRAM", program)
            .env("NERVE_TEST_ARGS", args.join("\n"))
            .current_dir(cwd)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let code = text
            .lines()
            .find_map(|l| l.strip_prefix("exit code: "))
            .unwrap_or_else(|| panic!("no exit code: {text}"))
            .trim()
            .parse()
            .unwrap();
        (code, text)
    }

    /// Run by [`run_in_container`] in a process of its own.
    #[cfg(windows)]
    #[test]
    #[ignore = "a helper of the AppContainer tests"]
    fn helper_runs_in_a_container() {
        let var = |k: &str| std::env::var(k).unwrap();
        let args: Vec<String> = var("NERVE_TEST_ARGS")
            .split('\n')
            .map(String::from)
            .collect();
        let program = var("NERVE_TEST_PROGRAM");
        // A container that may not enter its working folder does not start.
        match appcontainer::run(
            std::path::Path::new(&program),
            &args,
            &var("NERVE_TEST_CONTAINER"),
        ) {
            Ok(code) => println!("exit code: {code}"),
            Err(e) => println!("exit code: {}\n{e}", u32::MAX),
        }
    }

    /// A command in the container reads and writes its granted folder and
    /// reaches nothing outside it; once the grant is off, the folder is
    /// closed too.
    #[cfg(windows)]
    #[test]
    fn an_appcontainer_reaches_its_granted_folder_only() {
        let base = tempfile::tempdir().unwrap();
        let granted = base.path().join("granted");
        let other = base.path().join("other");
        std::fs::create_dir_all(granted.join("sub")).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(granted.join("sub").join("in.txt"), "inside").unwrap();
        std::fs::write(other.join("secret.txt"), "secret").unwrap();
        let name = format!("nerve.test.{}", std::process::id());
        appcontainer::set(&granted, &name, Some(acl::masks(true, true, true))).unwrap();
        let d = |p: &std::path::Path| p.display().to_string();
        let run = |command: String| in_container(&name, &granted, &command);

        assert_eq!(run(r"type sub\in.txt > copy.txt".into()), 0);
        assert_eq!(
            std::fs::read_to_string(granted.join("copy.txt"))
                .unwrap()
                .trim(),
            "inside"
        );
        assert_ne!(
            run(format!(r#"type "{}\secret.txt" > leak.txt"#, d(&other))),
            0
        );
        let leak = std::fs::read_to_string(granted.join("leak.txt")).unwrap_or_default();
        assert!(!leak.contains("secret"), "{leak}");
        assert_ne!(run(format!(r#"echo x> "{}\new.txt""#, d(&other))), 0);
        assert!(!other.join("new.txt").exists());

        appcontainer::set(&granted, &name, None).unwrap();
        assert_ne!(run(r"type sub\in.txt > copy2.txt".into()), 0);
        assert!(!granted.join("copy2.txt").exists());
        appcontainer::remove_profile(&name).unwrap();
    }

    /// The flags are independent in the container too: a folder with `w`
    /// alone is written and not read or listed, one with `x` alone runs its
    /// program (and reads it by name) and is not listed or written.
    #[cfg(windows)]
    #[test]
    fn an_appcontainer_keeps_write_and_execute_apart_from_read() {
        let base = tempfile::tempdir().unwrap();
        let (work, wo, xo) = (
            base.path().join("work"),
            base.path().join("wo"),
            base.path().join("xo"),
        );
        for d in [&work, &wo, &xo] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(wo.join("old.txt"), "old").unwrap();
        std::fs::write(xo.join("tool.cmd"), "@echo tool ran> \"%~1\"\r\n").unwrap();
        let system = std::env::var("SystemRoot").unwrap();
        std::fs::copy(
            std::path::Path::new(&system)
                .join("System32")
                .join("hostname.exe"),
            xo.join("hostname.exe"),
        )
        .unwrap();
        let name = format!("nerve.test.flags.{}", std::process::id());
        let grant = |p: &std::path::Path, r, w, x| {
            appcontainer::set(p, &name, Some(acl::masks(r, w, x))).unwrap()
        };
        grant(&work, true, true, true);
        grant(&wo, false, true, false);
        grant(&xo, false, false, true);
        let (w, x) = (wo.display(), xo.display());
        let run = |c: String| in_container(&name, &work, &c);

        // cmd opens a file it redirects to for reading as well, so the
        // write goes through .NET, which opens it for writing only.
        let write = format!(r#"[IO.File]::WriteAllText('{w}\new.txt', 'x')"#);
        let (code, log) = run_in_container(
            &name,
            &work,
            "powershell.exe",
            &["-NoProfile", "-Command", &write],
        );
        assert_eq!(code, 0, "{log}");
        assert_eq!(
            std::fs::read_to_string(wo.join("new.txt")).unwrap().trim(),
            "x"
        );
        assert_ne!(run(format!(r#"type "{w}\old.txt" > got.txt"#)), 0);
        assert_ne!(run(format!(r#"dir "{w}" > list.txt"#)), 0);

        let out = work.join("ran.txt");
        let ps = |c: String| {
            run_in_container(
                &name,
                &work,
                "powershell.exe",
                &["-NoProfile", "-Command", &c],
            )
        };
        let (code, log) = ps(format!(
            "{POWERSHELL_START}& '{x}\\tool.cmd' '{}'; & '{x}\\hostname.exe' > host.txt; \
             exit $LASTEXITCODE",
            out.display()
        ));
        assert_eq!(code, 0, "{log}");
        assert_eq!(
            std::fs::read_to_string(&out)
                .unwrap_or_else(|e| panic!("{e}: {log}"))
                .trim(),
            "tool ran"
        );
        assert!(work.join("host.txt").exists(), "{log}");
        assert_ne!(run(format!(r#"dir "{x}" > list2.txt"#)), 0);
        assert_ne!(run(format!(r#"echo x> "{x}\no.txt""#)), 0);
        assert!(!xo.join("no.txt").exists());

        for d in [&work, &wo, &xo] {
            appcontainer::set(d, &name, None).unwrap();
        }
        appcontainer::remove_profile(&name).unwrap();
    }

    /// Windows PowerShell, the default shell, works in the container: it
    /// reads and writes its folder and is refused outside it.
    #[cfg(windows)]
    #[test]
    fn powershell_runs_in_an_appcontainer() {
        let base = tempfile::tempdir().unwrap();
        let granted = base.path().join("granted");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::write(granted.join("in.txt"), "inside").unwrap();
        std::fs::write(base.path().join("secret.txt"), "secret").unwrap();
        let name = format!("nerve.test.ps.{}", std::process::id());
        appcontainer::set(&granted, &name, Some(acl::masks(true, true, true))).unwrap();
        let script = format!(
            "{POWERSHELL_START}Get-Content in.txt | Set-Content out.txt; \
             mkdir sub | Out-Null; cd sub; Set-Content here.txt (cmd /c cd); cd ..; \
             try {{ Get-Content '{}' -ErrorAction Stop | Set-Content leak.txt }} \
             catch {{ Set-Content refused.txt $_.Exception.GetType().Name }}",
            base.path().join("secret.txt").display()
        );
        let (code, log) = run_in_container(
            &name,
            &granted,
            "powershell.exe",
            &["-NoProfile", "-Command", &script],
        );
        assert_eq!(code, 0, "{log}");
        assert_eq!(
            std::fs::read_to_string(granted.join("out.txt"))
                .unwrap_or_else(|e| panic!("{e}: {log}"))
                .trim(),
            "inside",
            "{log}"
        );
        // Native programs start where PowerShell stands.
        assert_eq!(
            std::fs::read_to_string(granted.join("sub").join("here.txt"))
                .unwrap_or_else(|e| panic!("{e}: {log}"))
                .trim(),
            granted.join("sub").display().to_string(),
            "{log}"
        );
        assert!(!granted.join("leak.txt").exists(), "{log}");
        let refused = std::fs::read_to_string(granted.join("refused.txt")).unwrap();
        assert!(refused.contains("UnauthorizedAccess"), "{refused} {log}");
        appcontainer::set(&granted, &name, None).unwrap();
        appcontainer::remove_profile(&name).unwrap();
    }

    /// Runs `script` in `/bin/sh` under `spec`; whether it succeeded.
    #[cfg(target_os = "linux")]
    fn confined_sh(spec: &LandlockSpec, script: &str) -> bool {
        use std::os::unix::process::CommandExt;
        let mut rs = Some(landlock_rules::prepare(spec).unwrap());
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        // SAFETY: the closure only makes the Landlock syscalls on a ruleset
        // built before the fork.
        unsafe {
            cmd.pre_exec(move || match rs.take() {
                Some(r) => landlock_rules::enforce(r),
                None => Ok(()),
            });
        }
        cmd.status().unwrap().success()
    }

    /// The rules hold in a real child: writes inside the read-write folder
    /// work, writes elsewhere fail. Skipped where the kernel has no Landlock.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_confines_writes() {
        if landlock_rules::abi_version().is_none() {
            eprintln!("no Landlock here; skipped");
            return;
        }
        let tmp = std::env::temp_dir();
        let rw = tempfile::tempdir_in(&tmp).unwrap();
        let other = tempfile::tempdir_in(&tmp).unwrap();
        let spec = LandlockSpec {
            read: [system_dirs(), vec![rw.path().into()]].concat(),
            write: [system_writable(), vec![rw.path().into()]].concat(),
            exec: system_dirs(),
        };
        let run = |target: &std::path::Path| {
            confined_sh(&spec, &format!("echo x > {}", target.display()))
        };
        assert!(run(&rw.path().join("ok")));
        assert!(rw.path().join("ok").exists());
        assert!(!run(&other.path().join("no")));
        assert!(!other.path().join("no").exists());
    }

    /// The flags are independent in the kernel too: a folder in `write` alone
    /// can be written and not read or listed, and one in `exec` alone can run
    /// its program and not be read.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_write_without_read_and_execute_without_read() {
        if landlock_rules::abi_version().is_none() {
            eprintln!("no Landlock here; skipped");
            return;
        }
        let tmp = std::env::temp_dir();
        let wo = tempfile::tempdir_in(&tmp).unwrap();
        let xo = tempfile::tempdir_in(&tmp).unwrap();
        std::fs::write(wo.path().join("old"), "old").unwrap();
        std::fs::copy("/bin/true", xo.path().join("tool")).unwrap();
        let spec = LandlockSpec {
            read: system_dirs(),
            write: [system_writable(), vec![wo.path().into()]].concat(),
            exec: [system_dirs(), vec![xo.path().into()]].concat(),
        };
        let d = |p: &std::path::Path| p.display().to_string();
        assert!(confined_sh(
            &spec,
            &format!("echo x > {}/new", d(wo.path()))
        ));
        assert_eq!(
            std::fs::read_to_string(wo.path().join("new")).unwrap(),
            "x\n"
        );
        assert!(!confined_sh(&spec, &format!("cat {}/old", d(wo.path()))));
        assert!(!confined_sh(&spec, &format!("ls {}", d(wo.path()))));
        assert!(confined_sh(&spec, &format!("{}/tool", d(xo.path()))));
        // Not listed, not written; a file can be read by name only because
        // Landlock cannot run what it may not read.
        assert!(!confined_sh(&spec, &format!("ls {}", d(xo.path()))));
        assert!(confined_sh(
            &spec,
            &format!("cat {}/tool > /dev/null", d(xo.path()))
        ));
        assert!(!confined_sh(
            &spec,
            &format!("echo x > {}/no", d(xo.path()))
        ));
        // Without the exec right the same program does not start.
        let none = LandlockSpec {
            exec: system_dirs(),
            ..spec.clone()
        };
        assert!(!confined_sh(&none, &format!("{}/tool", d(xo.path()))));
    }
}
