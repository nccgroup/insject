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

#[macro_use]
extern crate gumshoe;
//extern crate base64;
//extern crate cc;

/*
use base64::decode;

use std::fs::File;
use std::io::Write;

extern crate cc;

pub fn link() {
  let b64 = gumshoe::codeb64();
  let code = &decode(b64).unwrap();

  std::fs::create_dir_all("gen").unwrap();
  let mut f = File::create("gen/frida-gum-wrapper.c").expect("Unable to create file");
  f.write_all(code.as_slice()).expect("Unable to write data");

  println!("cargo:rustc-flags=-L frida/{}", std::env::var("TARGET").unwrap());
  println!("cargo:rustc-flags=-l frida-gum");
  println!("cargo:rustc-flags=-l dl");
  println!("cargo:rustc-flags=-l resolv");
  println!("cargo:rustc-flags=-l rt");
  println!("cargo:rustc-flags=-l m");
  println!("cargo:rustc-flags=-l pthread");

  cc::Build::new()
    .include("frida")
    .file("gen/frida-gum-wrapper.c")
    .compile("frida-gum-wrapper");
}
*/

link!{}

fn main() {
  link(true);
}


