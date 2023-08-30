use one_collect::perf_event::{
    self,
    PerfSession,
    RingBufBuilder,
    RingBufOptions,
    RingBufSessionBuilder
};

use one_collect::Writable;

struct Utilization {
    per_cpu: Vec<u64>,
    temp: String,
}

impl Utilization {
    fn create() -> Self {
        let cpu_count = perf_event::cpu_count() as usize;

        let mut per_cpu = Vec::new();
        per_cpu.resize(cpu_count, 0);

        Self {
            per_cpu,
            temp: String::new(),
        }
    }

    pub fn new(session: &mut PerfSession) -> Writable<Self> {
        let util = Writable::new(Self::create());

        /* CPU is ancillary data for perf_event_open */
        let ancillary = session.ancillary_data();

        /* Clone the writable for callback */
        let session_util = util.clone();

        /* Setup to inc cpu by 1 on each cpu profile */
        session
            .cpu_profile_event()
            .set_callback(move |_full_data,_event_format,_event_data| {
                let mut cpu: u32 = 0;

                ancillary.read(|values| {
                    cpu = values.cpu();
                });

                session_util.write(|usage| {
                    usage.per_cpu[cpu as usize] += 1;
                });
            });

        /* Give back the shared writable */
        util
    }

    pub fn report(&mut self) {
        let mut all = 0u64;

        println!(concat!(
            "\x1b[H\x1b[J\x1b[4m",
            "CPU│",
            "                    ",
            "Utilization",
            "                    ",
            " │  %\x1b[0m"));

        for (cpu,total) in self.per_cpu.iter().enumerate() {
            Self::print_graph(&mut self.temp, Some(cpu), *total);
            all += total;
        }

        let total = all / self.per_cpu.len() as u64;
        Self::print_graph(&mut self.temp, None, total);

        for total in &mut self.per_cpu {
            *total = 0;
        }
    }

    fn print_graph(
        temp: &mut String,
        cpu: Option<usize>,
        mut total: u64) {
        if total > 100 {
            total = 100;
        }

        let notches = total / 2;
        temp.clear();

        match total {
            /* Gray */
            0..=25 => { temp.push_str("\x1b[1;30;1m"); },

            /* Yellow */
            26..=75 => { temp.push_str("\x1b[1;33m"); },

            /* Red */
            _ => { temp.push_str("\x1b[1;31m"); }
        }

        for _ in 0..notches {
            temp.push('─');
        }

        temp.push_str("\x1b[0m");

        for _ in notches..50 {
            temp.push(' ');
        }

        match cpu {
            Some(cpu) => {
                println!("{:3}│ {} │{:2}%", cpu, temp, total);
            },
            None => {
                println!("SUM│ {} │{:2}%", temp, total);
            }
        }
    }
}

fn main() {
    let one_sec = std::time::Duration::from_secs(1);
    let need_permission = "Need permission (run via sudo?)";

    /* Default options */
    let options = RingBufOptions::default();

    /* Sample 100 times a sec (10 ms interrupts) */
    let freq = 100;
    let cpu = RingBufBuilder::for_profiling(&options, freq);

    /* Build up cpu session */
    let mut session = RingBufSessionBuilder::new()
        .with_page_count(4)
        .with_profiling_events(cpu)
        .build()
        .expect(need_permission);

    let util = Utilization::new(&mut session);

    loop {
        /* Print and reset utilization */
        util.write(|util| { util.report(); });

        /* Profile for 1 second */
        session.enable().expect(need_permission);
        std::thread::sleep(one_sec);
        session.disable().expect(need_permission);

        /* Parse captured data */
        session.parse_all().expect(need_permission);
    }
}
