package inbound

import "testing"

func TestKolmogorovSmirnovStatistic(t *testing.T) {
	a := []float64{1, 2, 3, 4, 5, 6, 7, 8}
	b := []float64{1.1, 2.1, 3.0, 4.2, 5.1, 6.2, 7.3, 8.1}
	c := []float64{100, 110, 120, 130, 140, 150, 160, 170}

	dClose := KolmogorovSmirnovStatistic(a, b)
	dFar := KolmogorovSmirnovStatistic(a, c)
	if !(dClose < dFar) {
		t.Fatalf("expected close distributions to have lower D: close=%f far=%f", dClose, dFar)
	}
}
