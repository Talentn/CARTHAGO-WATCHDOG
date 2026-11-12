package analyzer

import (
	"math"
	"sort"
)

func mean(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range x {
		s += v
	}
	return s / float64(len(x))
}

// stddev is the sample standard deviation.
func stddev(x []float64) float64 {
	if len(x) < 2 {
		return 0
	}
	m := mean(x)
	s := 0.0
	for _, v := range x {
		s += (v - m) * (v - m)
	}
	return math.Sqrt(s / float64(len(x)-1))
}

func median(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	s := append([]float64(nil), x...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// mad is the median absolute deviation, scaled by 1.4826 so it estimates the standard
// deviation of a normal distribution. It ignores outliers, which is the point: one cheater in
// the sample must not widen the band that should catch them.
func mad(x []float64) float64 {
	m := median(x)
	d := make([]float64, len(x))
	for i, v := range x {
		d[i] = math.Abs(v - m)
	}
	return 1.4826 * median(d)
}

// robustZ is how many robust standard deviations v sits from the median of population.
func robustZ(v float64, population []float64) float64 {
	s := mad(population)
	if s == 0 {
		return 0
	}
	return (v - median(population)) / s
}

// binomialZ is the normal-approximation z-score of k successes in n trials against rate p.
func binomialZ(k, n int, p float64) float64 {
	if n == 0 || p <= 0 || p >= 1 {
		return 0
	}
	exp := float64(n) * p
	sd := math.Sqrt(float64(n) * p * (1 - p))
	return (float64(k) - exp) / sd
}

// binomialTail is the exact probability of k or more successes in n trials at rate p.
func binomialTail(k, n int, p float64) float64 {
	if k <= 0 {
		return 1
	}
	if n <= 0 || k > n || p <= 0 {
		return 0
	}
	if p >= 1 {
		return 1
	}
	lg := func(x int) float64 { v, _ := math.Lgamma(float64(x) + 1); return v }
	lp, lq := math.Log(p), math.Log1p(-p)
	sum := 0.0
	for i := k; i <= n; i++ {
		sum += math.Exp(lg(n) - lg(i) - lg(n-i) + float64(i)*lp + float64(n-i)*lq)
	}
	return math.Min(1, sum)
}

// normalTail is the one-sided tail probability of a standard normal beyond z, used to express
// a configured z threshold as the probability an exact test is held to.
func normalTail(z float64) float64 {
	return 0.5 * math.Erfc(z/math.Sqrt2)
}
