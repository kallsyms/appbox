use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindgen::Builder::default()
        .header("src/third_party/dyld_cache_format.h")
        .generate()
        .expect("Unable to generate dyld bindings")
        .write_to_file(out_dir.join("dyld_cache_format.rs"))
        .expect("Couldn't write dyld bindings");

    bindgen::Builder::default()
        .header("src/third_party/cpu_capabilities.h")
        .generate()
        .expect("Unable to generate commpage/cpu_capabilities bindings")
        .write_to_file(out_dir.join("commpage.rs"))
        .expect("Couldn't write commpage/cpu_capabilities bindings");

    // Generate syscall and Mach trap names map
    generate_syscalls_module(&out_dir);
}

fn generate_syscalls_module(out_dir: &PathBuf) {
    // Use the raw branch URL format (no refs/heads)
    const URL: &str = "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/syscalls.master";
    const MACH_URL: &str = "https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/kern/syscall_sw.c";

    // Allow overriding source via env for offline builds or testing
    println!("cargo:rerun-if-env-changed=APPBOX_SYSCALLS_MASTER_PATH");

    let syscalls_text = match env::var("APPBOX_SYSCALLS_MASTER_PATH") {
        Ok(path) => match fs::read_to_string(&path) {
            Ok(s) => Some(s),
            Err(e) => {
                println!("cargo:warning=appbox: failed to read {}: {}", path, e);
                None
            }
        },
        Err(_) => {
            // Try to fetch over the network
            match ureq::get(URL).call() {
                Ok(resp) => resp.into_string().ok(),
                Err(err) => {
                    println!(
                        "cargo:warning=appbox: failed to fetch syscalls.master: {}",
                        err
                    );
                    None
                }
            }
        }
    };

    let Some(text) = syscalls_text else {
        // Write a minimal empty module to keep builds working offline.
        let fallback = r#"// @generated (empty): syscalls list unavailable
pub static SYSCALLS: &[(u64, &str)] = &[];
pub fn syscall_name(_num: u64) -> Option<&'static str> { None }
"#;
        let _ = fs::write(out_dir.join("syscalls.rs"), fallback);
        println!("cargo:warning=appbox: syscalls.rs generated empty (no source available)");
        return;
    };

    // Parse syscalls.master lines into (number, name)
    let mut entries: Vec<(u64, String)> = Vec::new();
    // Keep BSD syscalls separately for constants
    let mut sys_by_number: Vec<(u64, String)> = Vec::new();
    // Collect Mach traps by positive index for a separate table
    let mut mach_by_index: Vec<(u64, String)> = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Column 0 is the syscall number
        let first_token = line.split_whitespace().next().unwrap_or("");
        let Ok(num) = first_token.parse::<u64>() else {
            continue;
        };

        // Extract the prototype between the first '{' and the next '}'
        let Some(lbrace) = line.find('{') else {
            continue;
        };
        let Some(rbrace) = line[lbrace + 1..].find('}') else {
            continue;
        };
        let proto = &line[lbrace + 1..lbrace + 1 + rbrace];
        let proto = proto.trim();

        // Find the function name: the identifier right before the first '('
        let Some(paren_idx) = proto.find('(') else {
            continue;
        };
        let pre = proto[..paren_idx].trim();
        if pre.is_empty() {
            continue;
        }
        let mut name_token = pre.split_whitespace().last().unwrap_or("");
        // Handle pointer return types like "void *mmap"
        name_token = name_token.trim_start_matches('*');
        if name_token.is_empty() {
            continue;
        }

        entries.push((num, name_token.to_string()));
        sys_by_number.push((num, name_token.to_string()));
    }

    // Sort and deduplicate by syscall number (keep the first occurrence)
    entries.sort_by_key(|e| e.0);
    entries.dedup_by_key(|e| e.0);

    // Also parse Mach trap names from syscall_sw.c and add them with negative numbers
    println!("cargo:rerun-if-env-changed=APPBOX_MACH_SYSCALL_SW_PATH");
    let mach_text = match env::var("APPBOX_MACH_SYSCALL_SW_PATH") {
        Ok(path) => fs::read_to_string(path).ok(),
        Err(_) => match ureq::get(MACH_URL).call() {
            Ok(resp) => resp.into_string().ok(),
            Err(_) => None,
        },
    };

    if let Some(mtext) = mach_text {
        if let Some(start_idx) = mtext.find("mach_syscall_name_table") {
            if let Some(brace_idx) = mtext[start_idx..].find('{') {
                let after_brace = start_idx + brace_idx + 1;
                if let Some(end_idx_rel) = mtext[after_brace..].find("};") {
                    let block = &mtext[after_brace..after_brace + end_idx_rel];
                    for line in block.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        // Expect pattern: /* N */ "name",
                        let Some(c_start) = line.find("/*") else {
                            continue;
                        };
                        let Some(c_end) = line.find("*/") else {
                            continue;
                        };
                        if c_end <= c_start {
                            continue;
                        }
                        let num_str = line[c_start + 2..c_end].trim();
                        let Ok(idx) = num_str.parse::<u64>() else {
                            continue;
                        };

                        let Some(q1) = line.find('"') else { continue };
                        let rest = &line[q1 + 1..];
                        let Some(q2rel) = rest.find('"') else {
                            continue;
                        };
                        let name = &rest[..q2rel];
                        let key = 0u64.wrapping_sub(idx);
                        entries.push((key, name.to_string()));
                        mach_by_index.push((idx, name.to_string()));
                    }
                }
            }
        }
    }

    // Sort and dedup again after adding Mach traps
    entries.sort_by_key(|e| e.0);
    entries.dedup_by_key(|e| e.0);
    sys_by_number.sort_by_key(|e| e.0);
    sys_by_number.dedup_by_key(|e| e.0);
    mach_by_index.sort_by_key(|e| e.0);
    mach_by_index.dedup_by_key(|e| e.0);

    let mut out = String::new();
    out.push_str("// @generated by build.rs from xnu syscalls.master and syscall_sw.c\n");
    out.push_str("\n/// Combined map of BSD syscalls and Mach traps.\n");
    out.push_str("///\n");
    out.push_str("/// - BSD syscalls use their positive syscall numbers.\n");
    out.push_str(
        "/// - Mach traps are keyed as negative numbers encoded via `0u64.wrapping_sub(index)`.\n",
    );
    out.push_str("pub static SYSCALLS: &[(u64, &str)] = &[\n");
    for (n, name) in &entries {
        out.push_str(&format!("    ({}, \"{}\"),\n", n, name));
    }
    out.push_str("];\n");
    out.push_str("\n/// Lookup a name by number. Includes both BSD syscalls and Mach traps.\n");
    out.push_str("///\n");
    out.push_str("/// - For BSD syscalls, pass the positive syscall number.\n");
    out.push_str("/// - For Mach traps, pass `0u64.wrapping_sub(index)` (negative encoding).\n");
    out.push_str(
        "pub fn syscall_name(num: u64) -> Option<&'static str> {\n    SYSCALLS.iter().find_map(|(n, name)| if *n == num { Some(*name) } else { None })\n}\n",
    );

    // Separate Mach traps table and helpers
    out.push_str("\n/// Mach traps table keyed by positive trap index.\n");
    out.push_str("pub static MACH_TRAPS: &[(u64, &str)] = &[\n");
    for (idx, name) in &mach_by_index {
        out.push_str(&format!("    ({}, \"{}\"),\n", idx, name));
    }
    out.push_str("];\n");
    out.push_str("\n/// Get Mach trap name by its positive index.\n");
    out.push_str(
        "pub fn mach_trap_name(index: u64) -> Option<&'static str> {\n    MACH_TRAPS.iter().find_map(|(i, name)| if *i == index { Some(*name) } else { None })\n}\n",
    );

    // Constants for BSD syscalls and Mach traps
    out.push_str("\n/// Constants for BSD syscalls (positive numbers).\n");
    {
        let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (num, name) in &sys_by_number {
            // Strip optional leading "sys_" from symbol name for constant naming
            let base = name.strip_prefix("sys_").unwrap_or(name);
            let mut cname = format!("SYS_{}", base);
            if !used.insert(cname.clone()) {
                cname = format!("SYS_{}_{}", base, num);
                let _ = used.insert(cname.clone());
            }
            out.push_str(&format!("pub const {}: u64 = {}u64;\n", cname, num));
        }
    }

    out.push_str("\n/// Constants for Mach traps (encoded as negative numbers in u64).\n");
    out.push_str("/// For trap index N, the encoded key equals `0u64.wrapping_sub(N)`.\n");
    {
        let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (idx, raw_name) in &mach_by_index {
            let mut core = raw_name.trim_start_matches('_').to_string();
            if let Some(stripped) = core.strip_prefix("kernelrpc_") {
                core = stripped.to_string();
            }
            if let Some(stripped) = core.strip_suffix("_trap") {
                core = stripped.to_string();
            }
            let mut cname = format!("TRAP_{}", core);
            if !used.insert(cname.clone()) {
                cname = format!("TRAP_{}_{}", core, idx);
                let _ = used.insert(cname.clone());
            }
            out.push_str(&format!(
                "pub const {}: u64 = (-{}i64) as u64;\n",
                cname, idx
            ));
        }
    }

    if let Err(e) = fs::write(out_dir.join("syscalls.rs"), out) {
        println!(
            "cargo:warning=appbox: failed to write generated syscalls.rs: {}",
            e
        );
    }
}
