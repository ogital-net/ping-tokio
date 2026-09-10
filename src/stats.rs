use std::time::Duration;

/// RTT statistics shared by the library and command-line binary.
#[derive(Debug, Default)]
pub(crate) struct RttStats {
    pub(crate) rtt_min: Duration,
    pub(crate) rtt_avg: Duration,
    pub(crate) rtt_max: Duration,
    pub(crate) rtt_std_dev: Duration,
}

/// Compute population statistics; empty input produces zero durations.
///
/// The mean is truncated to whole nanoseconds. Standard deviation is computed
/// in floating-point seconds and rounded to the nearest nanosecond.
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
pub(crate) fn compute_rtt_stats(rtts: &[Duration]) -> RttStats {
    if rtts.is_empty() {
        return RttStats::default();
    }

    let min = *rtts.iter().min().unwrap();
    let max = *rtts.iter().max().unwrap();
    let count = rtts.len() as u128;

    // Quotient/remainder sums keep the mean within the input range.
    let (quotients, remainders) = rtts.iter().fold((0u128, 0u128), |(q, r), sample| {
        let nanos = sample.as_nanos();
        (q + nanos / count, r + nanos % count)
    });
    let avg_nanos = quotients + remainders / count;
    let avg = Duration::new(
        (avg_nanos / 1_000_000_000) as u64,
        (avg_nanos % 1_000_000_000) as u32,
    );
    let fractional_mean_secs = (remainders % count) as f64 / count as f64 * 1e-9;

    // Deviations are centered on the exact mean, including the fractional
    // nanosecond omitted from the reported mean.
    let mut squared_sum = 0.0;
    let mut compensation = 0.0;
    for &sample in rtts {
        let delta = if sample >= avg {
            (sample - avg).as_secs_f64() - fractional_mean_secs
        } else {
            -(avg - sample).as_secs_f64() - fractional_mean_secs
        };
        // Kahan summation.
        let term = delta * delta - compensation;
        let next_sum = squared_sum + term;
        compensation = (next_sum - squared_sum) - term;
        squared_sum = next_sum;
    }

    let std_dev = Duration::from_secs_f64((squared_sum / count as f64).sqrt());
    RttStats {
        rtt_min: min,
        rtt_avg: avg,
        rtt_max: max,
        rtt_std_dev: std_dev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_outlier_does_not_overflow_squared_deviation() {
        let mut rtts = [
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(4999),
        ];
        // For [a, a, b], population standard deviation is (b - a) * sqrt(2) / 3.
        let expected = Duration::from_secs_f64(4.998 * 2.0_f64.sqrt() / 3.0);
        for _ in 0..2 {
            let stats = compute_rtt_stats(&rtts);
            assert_eq!(stats.rtt_min, Duration::from_millis(1));
            assert_eq!(stats.rtt_avg, Duration::from_millis(1667));
            assert_eq!(stats.rtt_max, Duration::from_millis(4999));
            assert!(stats.rtt_std_dev.abs_diff(expected) <= Duration::from_nanos(1));
            rtts.reverse();
        }
    }

    #[test]
    fn accumulated_variance_does_not_overflow() {
        let rtts: Vec<_> = (0..100)
            .map(|i| Duration::from_millis(if i % 2 == 0 { 1 } else { 999 }))
            .collect();
        let stats = compute_rtt_stats(&rtts);
        assert_eq!(stats.rtt_avg, Duration::from_millis(500));
        assert_eq!(stats.rtt_std_dev, Duration::from_millis(499));
    }

    #[test]
    fn realistic_samples_match_an_exact_integer_reference() {
        // Fixed-seed samples; bounds keep the u128 oracle exact.
        let mut seed = 1u64;
        for count in [1usize, 2, 3, 10, 100, 1000] {
            let rtts: Vec<_> = (0..count)
                .map(|_| {
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    Duration::from_nanos(seed % 5_000_000_001)
                })
                .collect();
            let n = count as u128;
            let sum: u128 = rtts.iter().map(Duration::as_nanos).sum();
            let sum_squares: u128 = rtts.iter().map(|d| d.as_nanos().pow(2)).sum();
            // Population variance = (n * sum(x^2) - sum(x)^2) / n^2.
            let numerator = n * sum_squares - sum * sum;
            let denominator = n * n;
            let floor_std_dev = (numerator / denominator).isqrt();
            let midpoint_squared = (2 * floor_std_dev + 1).pow(2);
            let round_up = 4 * numerator >= denominator * midpoint_squared;
            let expected_nanos = floor_std_dev + u128::from(round_up);
            let expected = Duration::from_nanos(u64::try_from(expected_nanos).unwrap());

            let stats = compute_rtt_stats(&rtts);
            assert_eq!(stats.rtt_avg.as_nanos(), sum / n);
            assert!(
                stats.rtt_std_dev.abs_diff(expected) <= Duration::from_nanos(1),
                "{count} samples: got {:?}, expected {expected:?}",
                stats.rtt_std_dev,
            );
        }
    }

    #[test]
    fn large_sample_sum_does_not_overflow() {
        // Sample fits in u64 nanoseconds; the sum does not.
        let sample = Duration::from_secs(10_000_000_000);
        let stats = compute_rtt_stats(&[sample; 4]);
        assert_eq!(stats.rtt_avg, sample);
        assert_eq!(stats.rtt_std_dev, Duration::ZERO);
    }

    #[test]
    fn large_durations_retain_nanosecond_differences() {
        // Larger than u64 nanoseconds.
        let base = Duration::from_secs(20_000_000_000);
        let stats = compute_rtt_stats(&[base, base + Duration::from_nanos(2)]);
        assert_eq!(stats.rtt_min, base);
        assert_eq!(stats.rtt_avg, base + Duration::from_nanos(1));
        assert_eq!(stats.rtt_max, base + Duration::from_nanos(2));
        assert_eq!(stats.rtt_std_dev, Duration::from_nanos(1));
    }

    #[test]
    fn maximum_durations_are_supported() {
        for rtts in [&[Duration::MAX][..], &[Duration::MAX; 3][..]] {
            let stats = compute_rtt_stats(rtts);
            assert_eq!(stats.rtt_min, Duration::MAX);
            assert_eq!(stats.rtt_avg, Duration::MAX);
            assert_eq!(stats.rtt_max, Duration::MAX);
            assert_eq!(stats.rtt_std_dev, Duration::ZERO);
        }
    }

    #[test]
    fn full_duration_range_is_supported() {
        let stats = compute_rtt_stats(&[Duration::ZERO, Duration::MAX]);
        assert_eq!(stats.rtt_avg, Duration::MAX / 2);
        // Half the range rounds to exactly 2^63 seconds in f64.
        assert_eq!(stats.rtt_std_dev, Duration::from_secs(1u64 << 63));
    }

    #[test]
    fn variance_uses_the_unrounded_mean() {
        let stats = compute_rtt_stats(&[Duration::ZERO, Duration::ZERO, Duration::from_nanos(1)]);
        assert_eq!(stats.rtt_avg, Duration::ZERO);
        // sqrt(2)/3 ns rounds to 0 ns. Centering only on the truncated mean
        // would produce sqrt(1/3) ns, which incorrectly rounds to 1 ns.
        assert_eq!(stats.rtt_std_dev, Duration::ZERO);
    }
}
