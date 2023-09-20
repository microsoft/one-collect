mod commandline;
mod debug;

fn main() {
  // Parse command line arguments.
  commandline::CommandLineParser::build().parse();
}