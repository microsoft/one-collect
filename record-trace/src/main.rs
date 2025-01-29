mod commandline;
mod export;
mod recorder;

use commandline::RecordArgs;
use recorder::Recorder;

fn main() {
    let mut recorder = Recorder::new(RecordArgs::parse());
    recorder.run();
}