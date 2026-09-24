use clap::Parser;

use appbox::gdb::GdbHooks;
use appbox::guest::{Guest, Program};

#[derive(Parser)]
pub struct Args {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// Port to listen on for a gdb client
    #[clap(long)]
    pub gdb_port: Option<u16>,

    /// Wait for gdb connection before running
    #[clap(long)]
    pub gdb_wait: bool,

    /// Target executable
    #[clap(required = true)]
    pub executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let program = appbox::guest::prepare()?.unwrap_or_else(|| {
        let mut argv = vec![args.executable.clone()];
        argv.extend(args.arguments.iter().cloned());
        Program::new(&args.executable, argv, vec![])
    });

    let mut guest = Guest::builder(program);
    if let Some(port) = args.gdb_port {
        guest = guest.hooks(GdbHooks::new(port, args.gdb_wait)?);
    }
    let end = guest.run()?;
    println!("guest ended: {end:?}");
    end.end_process()
}
