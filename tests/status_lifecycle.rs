//! Model-based test for `cosaci::status::StatusMachine`.
//!
//! Encodes the falsifiable claims of `hypotheses/status-lifecycle.md`
//! (SPEC.md §11.2, class A). Pure-DAG state machine: `Pending → Running →
//! QuorumVerifying → {Success | Failure}`, no skips, no backward edges,
//! no egress from terminals.

use cosaci::status::{is_allowed, is_terminal, Status, StatusMachine, TransitionError};
use hegel::{generators, TestCase};

const STATES: [Status; 5] = [
    Status::Pending,
    Status::Running,
    Status::QuorumVerifying,
    Status::Success,
    Status::Failure,
];

fn draw_status(tc: &TestCase) -> Status {
    let i = tc.draw(generators::integers::<usize>().min_value(0).max_value(4));
    STATES[i]
}

struct StatusTest {
    subject: StatusMachine,
    current: Status,
    history: Vec<Status>,
    ever_terminal: Option<Status>,
}

#[hegel::state_machine]
impl StatusTest {
    // Attempt any transition. Outcome must match the allowed-edge predicate.
    #[rule]
    fn attempt_transition(&mut self, tc: TestCase) {
        let target = draw_status(&tc);
        let before = self.current;
        let was_terminal = is_terminal(before);
        let legal = !was_terminal && is_allowed(before, target);

        match self.subject.transition(target) {
            Ok(new_state) => {
                assert!(
                    legal,
                    "subject accepted illegal transition {:?} -> {:?}",
                    before, target
                );
                assert_eq!(new_state, target);
                assert_eq!(self.subject.current(), target);
                self.current = target;
                self.history.push(target);
                if is_terminal(target) && self.ever_terminal.is_none() {
                    self.ever_terminal = Some(target);
                }
            }
            Err(TransitionError::IllegalTransition { from, to }) => {
                assert!(
                    !legal,
                    "subject rejected legal transition {:?} -> {:?}",
                    before, target
                );
                assert!(!was_terminal);
                assert_eq!(from, before);
                assert_eq!(to, target);
                assert_eq!(self.subject.current(), before);
            }
            Err(TransitionError::AlreadyTerminal { current }) => {
                assert!(was_terminal, "AlreadyTerminal on non-terminal {:?}", before);
                assert_eq!(current, before);
                assert_eq!(self.subject.current(), before);
            }
        }
    }

    // Structural invariants.
    #[invariant]
    fn model_matches_subject(&mut self, _: TestCase) {
        assert_eq!(self.subject.current(), self.current);
    }

    // Terminal stability: once we reach Success or Failure, current never
    // leaves that state regardless of subsequent rules.
    #[invariant]
    fn terminal_is_stable(&mut self, _: TestCase) {
        if let Some(terminal) = self.ever_terminal {
            assert_eq!(
                self.current, terminal,
                "terminal state {:?} was escaped",
                terminal
            );
        }
    }

    // No skipped transitions: every consecutive pair in history is in the
    // allowed edge set.
    #[invariant]
    fn history_has_no_illegal_edges(&mut self, _: TestCase) {
        for pair in self.history.windows(2) {
            let (from, to) = (pair[0], pair[1]);
            assert!(
                is_allowed(from, to),
                "history contains illegal edge {:?} -> {:?}",
                from,
                to
            );
        }
    }
}

#[hegel::test]
fn status_machine_matches_dag(tc: TestCase) {
    let test = StatusTest {
        subject: StatusMachine::new(),
        current: Status::Pending,
        history: vec![Status::Pending],
        ever_terminal: None,
    };
    hegel::stateful::run(test, tc);
}
