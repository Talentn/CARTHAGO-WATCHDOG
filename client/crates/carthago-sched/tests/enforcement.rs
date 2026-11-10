use std::time::Duration;

use carthago_sched::{clock, Config, Ctx, Job, JobBudget, Scheduler, Step};

struct Spin {
    name: &'static str,
    step_ns: u64,
    budget: JobBudget,
}

impl Job for Spin {
    fn name(&self) -> &'static str {
        self.name
    }
    fn budget(&self) -> JobBudget {
        self.budget
    }
    fn begin(&mut self) {}
    fn step(&mut self, _: &Ctx<'_>) -> Step {
        let t = clock::now_ns();
        while clock::now_ns() - t < self.step_ns {
            std::hint::spin_loop();
        }
        Step::Continue
    }
}

fn cfg(fraction: f64) -> Config {
    Config { cpu_fraction_gameplay: fraction, hitch_guard: None, eco_qos: false, ..Config::default() }
}

#[test]
fn overrunning_job_is_backed_off_then_quarantined() {
    let hog = Spin {
        name: "hog",
        step_ns: 5_000_000,
        budget: JobBudget {
            period_gameplay: Some(Duration::from_millis(20)),
            period_idle: None,
            max_step: Duration::from_micros(100),
            max_cpu_per_run: Duration::from_secs(1),
            share: 1.0,
            priority: 0,
        },
    };
    let s = Scheduler::start(cfg(0.5), vec![Box::new(hog)]).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let st = s.stop();
    let j = &st.jobs[0];
    assert!(j.quarantined, "{j:?}");
    assert_eq!(j.overruns, 3);
    assert_eq!(j.steps, 3);
}

#[test]
fn greedy_job_is_held_to_global_budget() {
    let greedy = Spin {
        name: "greedy",
        step_ns: 100_000,
        budget: JobBudget {
            period_gameplay: Some(Duration::from_millis(1)),
            period_idle: None,
            max_step: Duration::from_micros(200),
            max_cpu_per_run: Duration::from_secs(100),
            share: 1.0,
            priority: 0,
        },
    };
    let s = Scheduler::start(cfg(0.02), vec![Box::new(greedy)]).unwrap();
    let t = clock::now_ns();
    std::thread::sleep(Duration::from_secs(2));
    let st = s.stop();
    let wall = (clock::now_ns() - t) as f64;
    let allowed = wall * 0.02 + 6e6;
    assert!((st.charged_cpu_ns as f64) <= allowed * 1.05, "charged {} allowed {}", st.charged_cpu_ns, allowed);
    assert!((st.charged_cpu_ns as f64) >= wall * 0.02 * 0.7, "under-used: {}", st.charged_cpu_ns);
    assert!(st.slice_cpu.max_ns < 3_000_000);
}
