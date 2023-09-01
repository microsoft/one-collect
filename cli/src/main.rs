mod commandline;

fn main() {
  // Parse command line arguments.
  commandline::CommandLineParser::build().parse();
}