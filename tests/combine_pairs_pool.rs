#![cfg(feature = "multicore")]

use incrementalmerkletree::{frontier::Frontier, Hashable, Level};
use sapling_crypto::Node;

// This integration test runs in its own process, before any other test can initialize rayon.
#[test]
fn small_batches_leave_the_global_pool_uninitialized() {
    let node = Node::empty_leaf();
    let level = Level::from(0);
    let pairs = vec![(&node, &node); 1000];
    for width in [0, 1, 33, 63] {
        let expected = vec![Node::combine(level, &node, &node); width];
        assert_eq!(
            Node::combine_pairs(level, pairs[..width].iter().copied()),
            expected
        );
        assert_eq!(
            Node::combine_pairs(
                level,
                pairs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i < width)
                    .map(|(_, pair)| *pair),
            ),
            expected
        );
        let mut input = pairs[..width].iter().copied();
        assert_eq!(
            Node::combine_pairs(level, core::iter::from_fn(|| input.next())),
            expected
        );
    }

    let mut frontier = Frontier::<Node, 32>::empty();
    assert!(frontier.append_batch(&[node; 4]));

    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_global()
        .expect("small batches must not initialize the global rayon pool");
}
