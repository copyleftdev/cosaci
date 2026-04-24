//! Model-based test for `cosaci::registry::Registry`.
//!
//! Encodes the falsifiable claims of `hypotheses/registry-algebra.md`
//! (SPEC.md §5.2a, class A). Uses `#[hegel::state_machine]` to drive
//! `register / deregister / lookup / request_lease` against a `HashMap`
//! oracle; the invariant asserts `subject == model` after every rule.

use std::collections::{HashMap, HashSet};

use cosaci::registry::{Registry, RunnerId, RunnerInfo};
use hegel::{TestCase, generators};

// Restrict the id space so rules collide usefully — with a full u64 range,
// `deregister` would essentially never hit a registered id.
const ID_MIN: RunnerId = 0;
const ID_MAX: RunnerId = 10;

fn draw_id(tc: &TestCase) -> RunnerId {
    tc.draw(
        generators::integers::<RunnerId>()
            .min_value(ID_MIN)
            .max_value(ID_MAX),
    )
}

fn draw_info(tc: &TestCase) -> RunnerInfo {
    let pubkey_v: Vec<u8> = tc.draw(generators::binary().min_size(32).max_size(32));
    let mut pubkey = [0_u8; 32];
    pubkey.copy_from_slice(&pubkey_v);
    RunnerInfo {
        pubkey,
        stake: tc.draw(generators::integers::<u64>()),
    }
}

struct RegistryTest {
    subject: Registry,
    model: HashMap<RunnerId, RunnerInfo>,
}

#[hegel::state_machine]
impl RegistryTest {
    // Register or overwrite a runner. Tests last-write-wins overwrite.
    #[rule]
    fn register(&mut self, tc: TestCase) {
        let id = draw_id(&tc);
        let info = draw_info(&tc);
        self.subject.register(id, info.clone());
        self.model.insert(id, info);
    }

    // Deregister a runner (may or may not be present).
    #[rule]
    fn deregister(&mut self, tc: TestCase) {
        let id = draw_id(&tc);
        self.subject.deregister(id);
        self.model.remove(&id);
    }

    // Exercise the `deregister is idempotent` clause directly: two calls
    // in a row must produce the same state as one call.
    #[rule]
    fn deregister_twice(&mut self, tc: TestCase) {
        let id = draw_id(&tc);
        self.subject.deregister(id);
        self.subject.deregister(id);
        self.model.remove(&id);
    }

    // Lookup returns the same value the model holds for this id.
    #[rule]
    fn lookup(&mut self, tc: TestCase) {
        let id = draw_id(&tc);
        let s = self.subject.lookup(id);
        let m = self.model.get(&id);
        assert_eq!(s, m, "lookup disagreed with model for id {}", id);
    }

    // Request-lease eligibility agrees with model membership.
    #[rule]
    fn request_lease(&mut self, tc: TestCase) {
        let id = draw_id(&tc);
        assert_eq!(
            self.subject.is_registered(id),
            self.model.contains_key(&id),
            "is_registered disagreed with model for id {}",
            id
        );
    }

    // Structural invariant: subject and model hold the same keys with
    // the same values. hegeltest 0.8.0 requires `&mut self` on invariants.
    #[invariant]
    fn subject_matches_model(&mut self, _: TestCase) {
        let subject_ids: HashSet<RunnerId> = self.subject.ids().collect();
        let model_ids: HashSet<RunnerId> = self.model.keys().copied().collect();
        assert_eq!(
            subject_ids, model_ids,
            "id sets diverged: subject={:?}, model={:?}",
            subject_ids, model_ids
        );
        for (id, info) in &self.model {
            assert_eq!(
                self.subject.lookup(*id),
                Some(info),
                "value diverged for id {}",
                id
            );
        }
        assert_eq!(self.subject.len(), self.model.len(), "cardinality diverged");
    }
}

#[hegel::test]
fn registry_matches_hashmap_model(tc: TestCase) {
    let test = RegistryTest {
        subject: Registry::new(),
        model: HashMap::new(),
    };
    hegel::stateful::run(test, tc);
}
