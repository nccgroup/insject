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

extern crate clap;
//use clap::AppSettings;
//pub use clap::Clap;
//pub use clap::AppSettings;
use clap::{Clap,AppSettings};

extern crate commands;
use commands::tokenizer::{tokenize,TokenType};

extern crate serde;
use serde::{Deserialize, Serialize};

extern crate serde_json;

#[derive(Clap,Clone,Debug,Deserialize,Serialize)]
#[clap(name = "libsetns.so", version = "1.0",
       author = "Jeff Dileo <jeff.dileo@nccgroup.com>",
       about = "An inject-/LD_PRELOAD-able shim to simplify container testing \
                by joining an external program\nrun with it into the Linux \
                namespaces of other processes.\n
WARNING: Be careful when accessing or executing files in \
         containers as they may
         be able to abuse the access \
         of the joined process to escape.",
       setting = AppSettings::ColoredHelp
)]
pub struct Opts {
  #[clap(short = 's', long = "symbol", name = "symbol",
         about = "Symbol to hook entry of instead of main")]
  pub sym_name: Option<String>,
  #[clap(short = '@', long = "raw-address", name = "address",
         about = "Raw memory address to hook instead of a symbol\nNote: This is not an offset")]
  pub raw_address: Option<usize>,
  #[clap(about = "PID to source namespaces from by default",
         validator = |val| { val.parse::<usize>().map_err(|_| format!("must be a non-negative number, got: {}", val)) } )]
  pub target_pid: Option<usize>,
  #[clap(short = '1', long, about = "Set user namespace before other namespaces")]
  pub userns_first: bool,

  #[clap(short, long, about = "Path to mount namespace to set")]
  pub mnt: Option<String>,
  #[clap(short, long, about = "Path to network namespace to set")]
  pub net: Option<String>,
  #[clap(short, long, about = "Path to time namespace to set")]
  pub time: Option<String>,
  #[clap(short, long, about = "Path to IPC namespace to set")]
  pub ipc: Option<String>,
  #[clap(short = 'h', long, about = "Path to UTS (hostname) namespace to set")]
  pub uts: Option<String>,
  #[clap(short, long, about = "Path to PID namespace to set")]
  pub pid: Option<String>,
  #[clap(short, long, about = "Path to cgroup namespace to set")]
  pub cgroup: Option<String>,
  #[clap(short, long, about = "Path to user namespace to set")]
  pub userns: Option<String>,

  #[clap(long, about = "<uid>[:<gid>[:<group,ids>]])",
         default_value = "0:0:0",
         validator = |val: &str| {
           let vals: std::vec::Vec<String> = val.split(':').into_iter().map(|s| s.to_string()).collect();
           if vals.len() > 3 {
             return Err("invalid number of parts".to_string());
           }
           for (i,v) in vals.iter().enumerate() {
             if i < 2 {
               match v.parse::<u32>() {
                 Ok(_) => {},
                 Err(err) => { return Err(format!("invalid uid/gid: {}", v)) }
               }
             } else {
               let groups: std::vec::Vec<String> = v.split(',').into_iter().map(|s| s.to_string()).collect();
               for g in groups.iter() {
                 match g.parse::<u32>() {
                   Ok(_) => {},
                   Err(err) => { return Err(format!("invalid group: {}", v)) }
                 }
               }
             }
           }
           Ok(val.to_string())
         }
  )]
  pub user: String,

  #[clap(short, long, name = "profile", about = "Alternate AppArmor profile to set")]
  pub apparmor_profile: Option<String>,

  #[clap(short = 'F', long, about = "Skip fork after entering PID namespace, if entering PID namespace")]
  pub no_fork: bool,

  #[clap(short = 'M', long, about = "Skip setting mount namespace")]
  pub no_mnt: bool,
  #[clap(short = 'N', long, about = "Skip setting network namespace")]
  pub no_net: bool,
  #[clap(short = 'T', long, about = "Skip setting time namespace")]
  pub no_time: bool,
  #[clap(short = 'I', long, about = "Skip setting IPC namespace")]
  pub no_ipc: bool,
  #[clap(short = 'H', long, about = "Skip setting UTS (hostname) namespace")]
  pub no_uts: bool,
  #[clap(short = 'P', long, about = "Skip setting PID namespace")]
  pub no_pid: bool,
  #[clap(short = 'C', long, about = "Skip setting cgroup namespace")]
  pub no_cgroup: bool,
  #[clap(short = 'U', long, about = "Skip setting user namespace")]
  pub no_userns: bool,

  #[clap(short = 'A', long, about = "Skip setting AppArmor profile")]
  pub no_apparmor: bool,

  #[clap(short = 'S', long, about = "Exit if any namespace attach fails")]
  pub strict: bool,
}

pub fn print_help(ret: i32) {
  match <Opts as clap::IntoApp>::into_app().print_help() {
    Ok(_) => {
      std::process::exit(ret);
    },
    Err(err) => {
      println!("{}", err);
      std::process::exit(1);
    }
  }
}

pub fn parse_opts(args: &String) -> Opts {
  //let args = "setns ".to_owned() + args;
  let tokens = tokenize(&args);
  match tokens {
    Ok(tokens) => {
      for (_, token) in tokens.clone().iter().enumerate() {
        if token.text == "--help" {
          print_help(0);
        }
      }
      let tokens: std::vec::Vec<String> = tokens.into_iter().filter_map(|t| {
        match t.token_type {
          TokenType::Word => Some(t.text.to_string()),
          _ => None
        }
      }).collect();
      parse_opts_parts(&tokens)
    },
    Err(err) => {
      println!("{}", err);
      std::process::exit(1)
    }
  }
}

pub fn parse_opts_parts(args: &std::vec::Vec<String>) -> Opts {
  let mut args = args.clone();
  args.insert(0, "setns".to_string());

  let opts = match Opts::try_parse_from(args.into_iter()) {
    Ok(opts) => {
      opts
    },
    Err(err) => {
      println!("{}", err);
      std::process::exit(1)
    }
  };

  if opts.target_pid.is_none() &&
     opts.mnt.is_none() &&
     opts.net.is_none() &&
     opts.time.is_none() &&
     opts.ipc.is_none() &&
     opts.uts.is_none() &&
     opts.pid.is_none() &&
     opts.cgroup.is_none() &&
     opts.userns.is_none() {

    println!("Error: Must have at least one of <target-pid> or namespace option set.");
    print_help(1);
  }

  // if opts.fork && opts.no_pid {
  //   println!("Error: -f,--fork not supported with -P, --no-pid");
  //   print_help(1);
  // }

  opts
}

pub fn to_json(opts: &Opts) -> Option<String> {
  let j = serde_json::to_string(opts);
  match j {
    Ok(s) => Some(s),
    Err(err) => {
      println!("failed to JSON encode opts, err: {}, opts: {:?}", err, opts);
      None
    }
  }
}

pub fn from_json(s: &str) -> Option<Opts> {
  let o = serde_json::from_str(s);
  match o {
    Ok(opts) => Some(opts),
    Err(err) => {
      println!("failed to deserialize as Opts, error: {}, s: {}", err, s);
      None
    }
  }
}
