/*
Copyright (c) NCC Group, 2021
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

extern crate gumshoe;
extern crate libc;
extern crate setns_common;

mod lib;
pub use lib::*;
// use std::io::Write;

extern crate clap;
use clap::{Clap,AppSettings,ArgSettings};

use std::vec::Vec;

use libc::*;

#[derive(Clap,Clone,Debug)]
#[clap(name = "insject", version = "1.0",
       author = "Jeff Dileo <jeff.dileo@nccgroup.com>",
       about = "A tool to simplify container testing that runs an arbitrary\n\
                command in the Linux namespaces of other processes.

WARNING: Be careful when accessing or executing files in containers as they may
         be able to abuse the access of the joined process to escape.

Note: The -! instrumentation mode has several differences from the LD_PRELOAD modes:
        * Forking is not supported
        * -S,--strict is not supported
        * errno values are not returned
",
       setting(AppSettings::ColoredHelp),
       setting(AppSettings::AllowLeadingHyphen),
       setting(AppSettings::TrailingVarArg),
)]
pub struct InsjectOpts {
  #[clap(long = "help-setns", about = "Prints help information for setns.so")]
  setns_help: bool,

  #[clap(short = '!', name = "pid", about = "PID to instrument", conflicts_with = "cmd")]
  instrument_pid: Option<usize>,

  #[clap(
    about = "setns.so options. For detailed information, use --help-setns",
    setting(ArgSettings::AllowHyphenValues),
  )]
  setns_opts: Vec<String>,

  #[clap(multiple = true, last = true, required = false)]
  cmd: Vec<String>,
}

pub fn print_help(ret: i32) {
  match <InsjectOpts as clap::IntoApp>::into_app().print_help() {
    Ok(_) => {
      std::process::exit(ret);
    },
    Err(err) => {
      println!("{}", err);
      std::process::exit(1);
    }
  }
}

fn main() {
  let opts = InsjectOpts::parse();
  //let opts = Opts::parse();

  if opts.setns_help {
    setns_common::print_help(0);
  }

  if opts.setns_opts.len() == 0 {
    println!("Error: <setns-opts>... were not provided");
    print_help(1);
  }

  //println!("opts: {:?}", opts);
  let setns_opts = setns_common::parse_opts_parts(&opts.setns_opts);
  //println!("setns_opts: {:?}", setns_opts);

  if opts.cmd.len() > 0 {
    run_cmd(&opts, &setns_opts);
  } else {
    attach_inject(&opts, &setns_opts);
  }

  return;

/*
  let pid = unsafe { fork() };

  if pid == 0 {
    println!("child: about to PTRACE_TRACEME");
    //let _ = unsafe { ptrace(PTRACE_TRACEME, 0, 0 as *const c_char, 0 as *const c_char) };
    println!("child: about to SIGSTOP");
    let _ = unsafe { raise(SIGSTOP) };
    println!("child: continued");

    extern "C" {
      static mut environ: *const *const c_char;
    }

    let cmd = std::ffi::CString::new(opts.cmd[0].clone()).unwrap();
    let cmd = cmd.as_ptr();

    let argv: Vec<std::ffi::CString> = opts.cmd.into_iter().map(|s| std::ffi::CString::new(s).unwrap()).collect();
    let mut argv_p: Vec<*const c_char> = vec!();

    for a in argv.iter() {
      argv_p.push(a.as_ptr());
    }
    argv_p.push(0 as *const c_char);

    let r = unsafe {
      execve(cmd, argv_p.as_ptr(), environ)
    };

    println!("execve: {}", r);
    std::process::exit(42);
  } else {
    println!("parent: child pid: {}", pid);
    let mut status: c_int = 0;
    let status_r = &mut status as *mut c_int;

    unsafe {
      waitpid(pid, status_r, WUNTRACED);
    }

    //let _ = unsafe { getchar() };
    println!("parent: waitpid->status: {}", status);

    let _ = unsafe { getchar() };

    //let ret = unsafe { ptrace (PTRACE_CONT, pid, 0 as *const c_char, 0 as *const c_char) };
    //println!("parent: ret: {}", ret);

    let output = std::process::Command::new("lldb")
                                       .arg("-x")
                                       .arg("-p")
                                       .arg(format!("{}", pid))
                                       .arg("-b")
                                       .arg("-o")
                                       .arg("continue")
                                       .output();
    println!("output: {:?}", output);

    //let ret = unsafe { ptrace (PTRACE_DETACH, pid, 0 as *const c_char, 0 as *const c_char) };
    //println!("parent: ret: {}", ret);

    let _ = unsafe { kill(pid, SIGCONT) };

    let _ = unsafe { wait(status_r) };

    let exit_code = unsafe { WEXITSTATUS(status) };
    println!("exit_code: {}", exit_code);

    std::process::exit(exit_code);

    return;


    let ret = unsafe { ptrace (PTRACE_CONT, pid, 0 as *const c_char, 0 as *const c_char) };
    println!("parent: ret: {}", ret);

    let _ = unsafe { getchar() };

    let res = unsafe {
      waitpid(pid, status_r, 0);
    };
    println!("parent: waitpid->status: {}", status);

    let _ = unsafe { getchar() };
  }
*/
}

fn run_cmd(opts: &InsjectOpts, setns_opts: &setns_common::Opts) {
  let cmd = &opts.cmd;

  let json_str = setns_common::to_json(setns_opts).unwrap();

  let self_path = std::fs::read_link("/proc/self/exe").unwrap();
  std::env::set_var("LD_PRELOAD", self_path.as_os_str());

  std::env::set_var("SETNS_JSON", json_str);

  let file = std::ffi::CString::new(cmd[0].clone()).unwrap();
  let argv_cs: std::vec::Vec<std::ffi::CString> = cmd.into_iter().map(|s|
    std::ffi::CString::new(s.clone()).unwrap()
  ).collect();

  let mut argv: std::vec::Vec<*const c_char> = argv_cs.iter().map(|cs| cs.as_ptr()).collect();
  argv.push(0 as *const c_char);

  unsafe {
    execvp(file.as_ptr(), argv.as_ptr());

    let s = std::ffi::CString::new("execvp").unwrap();
    perror(s.as_ptr());
  }
  std::process::exit(42);
}

fn attach_inject(insject_opts: &InsjectOpts, opts: &setns_common::Opts) {

  // if opts.fork {
  //   println!("Error: -f,--fork not supported with -! <pid>");
  //   print_help(1);
  // }

  if opts.strict {
    println!("Error: -S,--strict not supported with -! <pid>");
    print_help(1);
  }

  let mnt = match &opts.mnt {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/mnt", if opts.no_mnt { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };
  let net = match &opts.net {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/net", if opts.no_net { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };
  let time = match &opts.time {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/time", if opts.no_time { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };
  let ipc = match &opts.ipc {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/ipc", if opts.no_ipc { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };
  let uts = match &opts.uts {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/uts", if opts.no_uts { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };
  let pid = match &opts.pid {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/pid", if opts.no_pid { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };
  let cgroup = match &opts.cgroup {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/cgroup", if opts.no_cgroup { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };
  let user = match &opts.userns {
    Some(path) => path.clone(),
    None => format!("/proc/{}/ns/user", if opts.no_userns { -1 } else {
      match opts.target_pid {
        Some(pid) => pid as i32,
        None => -1
      }
    })
  };

  let user_parts: std::vec::Vec<&str> = opts.user.split(':').collect();
  let (uid, gid, groups) = match &*user_parts {
    &[uid, gid, groups] => { (uid, gid, groups) },
    &[uid, gid] => { (uid, gid, "0") },
    &[uid] => { (uid, "0", "0") },
    _ => unreachable!()
  };
  let groups_len = {
    let pieces: std::vec::Vec<&str> = groups.split(',').into_iter().collect();
    pieces.len()
  };
  let apparmor_profile: String = match &opts.apparmor_profile {
    Some(apparmor_profile) => (*apparmor_profile).clone(),
    None => if opts.no_apparmor {
      "unconfined".to_owned()
    } else {
      match &opts.target_pid {
        Some(pid) => {
          let profile = match std::fs::read_to_string(format!("/proc/{}/attr/current", pid)) {
            Ok(profile) => profile,
            Err(_) => "unconfined".to_string()
          };
          match profile.strip_suffix(" (enforce)\n") {
            Some(profile) => profile.to_owned(),
            None => profile
          }
        },
        None => "unconfined".to_owned()
      }
    }
  };
  let changeprofile = format!("changeprofile {}", apparmor_profile);
  let changeprofile_len = if apparmor_profile == "unconfined".to_owned() {
    0
  } else {
    changeprofile.len()
  };

  let code = format!("\
int mnt = (int)open(\"{mnt}\",0);\
int net = (int)open(\"{net}\",0);\
int time = (int)open(\"{time}\",0);\
int ipc = (int)open(\"{ipc}\",0);\
int uts = (int)open(\"{uts}\",0);\
int pid = (int)open(\"{pid}\",0);\
int cgroup = (int)open(\"{cgroup}\",0);\
int user = (int)open(\"{user}\",0);\
\
int attr_current = -1;\
if ({changeprofile_len} > 0) attr_current = (int)open(\"/proc/self/attr/current\", 1);\
\
const char* mnt_r = \"N/A\";\
const char* net_r = \"N/A\";\
const char* time_r = \"N/A\";\
const char* ipc_r = \"N/A\";\
const char* uts_r = \"N/A\";\
const char* pid_r = \"N/A\";\
const char* cgroup_r = \"N/A\";\
const char* userns_r = \"N/A\";\
\
const char* aa_r = \"N/A\";\
\
if ({user_first} == 1) {{ if (user != -1) userns_r = ((int)setns(user, 0) == 0) ? \"0\" : \"-1\"; }}\
\
if (mnt != -1) mnt_r = ((int)setns(mnt, 0) == 0) ? \"0\" : \"-1\";\
if (net != -1) net_r = ((int)setns(net, 0) == 0) ? \"0\" : \"-1\";\
if (time != -1) time_r = ((int)setns(time, 0) == 0) ? \"0\" : \"-1\";\
if (ipc != -1) ipc_r = ((int)setns(ipc, 0) == 0) ? \"0\" : \"-1\";\
if (uts != -1) uts_r = ((int)setns(uts, 0) == 0) ? \"0\" : \"-1\";\
if (pid != -1) pid_r = ((int)setns(pid, 0) == 0) ? \"0\" : \"-1\";\
if (cgroup != -1) cgroup_r = ((int)setns(cgroup, 0) == 0) ? \"0\" : \"-1\";\
\
if ({user_first} != 1) {{ if (user != -1) userns_r = ((int)setns(user, 0) == 0) ? \"0\" : \"-1\"; }}\
\
const unsigned int groups[{groups_len}] = {{ {groups} }};\
const char* groups_r = ((int)setgroups({groups_len}, groups) == 0) ? \"0\" : \"-1\";\
if (groups_r[0] == '-') (void)perror(\"setgroups\");\
const char* gid_r = ((int)setgid({gid}) == 0) ? \"0\" : \"-1\";\
const char* uid_r = ((int)setuid({uid}) == 0) ? \"0\" : \"-1\";\
\
const char* changeprofile = \"{changeprofile}\";\
if (attr_current != -1) aa_r = ((int)write(attr_current, changeprofile, {changeprofile_len}) != -1) ? \"{apparmor_profile}\" : \"-1\";\
if (attr_current != -1) (int)close(attr_current);\
if (mnt != -1) (int)close(mnt);\
if (net != -1) (int)close(net);\
if (time != -1) (int)close(time);\
if (ipc != -1) (int)close(ipc);\
if (uts != -1) (int)close(uts);\
if (pid != -1) (int)close(pid);\
if (cgroup != -1) (int)close(cgroup);\
if (user != -1) (int)close(user);\
\
(int)printf(\"setns -> mnt: %s, net: %s, time: %s, ipc: %s, uts: %s, pid: %s, cgroup: %s, userns: %s, apparmor: %s, user: %s/%s/%s\\n\", \
  mnt_r, net_r, time_r, ipc_r, uts_r, pid_r, cgroup_r, userns_r, aa_r, uid_r, gid_r, groups_r);\
(*(int*)__errno_location()) = 0;\
",
  mnt=mnt, net=net, time=time, ipc=ipc, uts=uts, pid=pid, cgroup=cgroup, user=user,
  user_first=opts.userns_first as u32, apparmor_profile=apparmor_profile, changeprofile=changeprofile, changeprofile_len=changeprofile_len,
  uid=uid, gid=gid, groups=groups, groups_len=groups_len);

  //println!("{}", code);
  let output = std::process::Command::new("lldb")
                                     .arg("-x")
                                     .arg("-p")
                                     .arg(format!("{}", insject_opts.instrument_pid.unwrap()))
                                     .arg("-b")
                                     .arg("-o")
                                     .arg(format!("call {}", code))
                                     .output();
  // println!("output: {:?}", output);

  // if opts.fork {
  //   let code = "pro hand -n false -p false -s false SIGSTOP\ncall int p = (int)fork(); if (p != 0) {(int)printf(\"(parent)pid: %d, child pid: %d\", (int)getpid(), p); (int)puts(\"\");while (1) {(int)sleep(1);int cs;int r = (int)waitpid();if ( r == -1 ) {(int)puts(\"wat\");(void)exit(1);} else {(int)puts(\"wat2\");(void)exit(0);}}} else {(int)printf(\"(child)pid: %d\", (int)getpid());(int)puts(\"\");(int)system(\"touch /tmp/wat\");}\n";
  //   let mut child = std::process::Command::new("lldb")
  //       .arg("-x")
  //       .arg("-p")
  //       .arg(format!("{}", insject_opts.instrument_pid.unwrap()))
  //       // .arg("-b")
  //       //.arg("-o")
  //       //.arg(format!("{}", code))
  //       .stdin(std::process::Stdio::piped())
  //       .stdout(std::process::Stdio::piped())
  //       .spawn()
  //       .expect("Failed to spawn child process");;
  //   let mut stdin = child.stdin.take().expect("Failed to open stdin");
  //   std::thread::spawn(move || {
  //     stdin.write_all(format!("{}", code).as_bytes()).expect("Failed to write to stdin");
  //   });
  //   let output = child.wait_with_output().expect("Failed to read stdout");
  //   println!("output2: {:?}", String::from_utf8_lossy(&output.stdout));
  // }
  let _ = output;
}
