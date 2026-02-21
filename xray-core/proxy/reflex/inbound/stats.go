package inbound

import "sort"

// KolmogorovSmirnovStatistic returns the two-sample KS D statistic.
func KolmogorovSmirnovStatistic(a, b []float64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 1.0
	}
	aa := append([]float64(nil), a...)
	bb := append([]float64(nil), b...)
	sort.Float64s(aa)
	sort.Float64s(bb)

	i, j := 0, 0
	var cdfA, cdfB, d float64
	for i < len(aa) && j < len(bb) {
		if aa[i] <= bb[j] {
			i++
			cdfA = float64(i) / float64(len(aa))
		} else {
			j++
			cdfB = float64(j) / float64(len(bb))
		}
		diff := cdfA - cdfB
		if diff < 0 {
			diff = -diff
		}
		if diff > d {
			d = diff
		}
	}
	for i < len(aa) {
		i++
		cdfA = float64(i) / float64(len(aa))
		diff := cdfA - cdfB
		if diff < 0 {
			diff = -diff
		}
		if diff > d {
			d = diff
		}
	}
	for j < len(bb) {
		j++
		cdfB = float64(j) / float64(len(bb))
		diff := cdfA - cdfB
		if diff < 0 {
			diff = -diff
		}
		if diff > d {
			d = diff
		}
	}

	return d
}
