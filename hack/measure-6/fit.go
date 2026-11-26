/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"errors"
	"math"
)

// point is one measured object: the counts x that its size is fitted against, and its sizes y, of which a fit takes
// one.
type point struct {
	x, y []float64
}

// column returns the points with their i-th size as their only one.
func column(points []point, i int) []point {
	out := make([]point, len(points))
	for j, p := range points {
		out[j] = point{x: p.x, y: []float64{p.y[i]}}
	}
	return out
}

// fit is the result of a least-squares fit: the coefficients of y = c0 + c1 x1 + c2 x2 ..., and the largest distance
// of a point's y from the fitted line, which shows how well the counts explain the sizes.
type fit struct {
	coefficients    []float64
	largestResidual float64
}

// leastSquares fits y = c0 + c1 x1 + ... to the points by least squares, through the normal equations solved by
// Gauss-Jordan elimination with partial pivoting. It fails when the points can't tell a term from the others, as when
// a count never varies or always varies with another.
func leastSquares(points []point) (fit, error) {
	if len(points) == 0 {
		return fit{}, errors.New("no points")
	}
	n := len(points[0].x) + 1
	// The augmented matrix [XᵀX | Xᵀy], where each row of X is 1 followed by a point's counts.
	a := make([][]float64, n)
	for i := range a {
		a[i] = make([]float64, n+1)
	}
	for _, p := range points {
		row := append([]float64{1}, p.x...)
		for i := range n {
			for j := range n {
				a[i][j] += row[i] * row[j]
			}
			a[i][n] += row[i] * p.y[0]
		}
	}
	for col := range n {
		pivot := col
		for r := col + 1; r < n; r++ {
			if math.Abs(a[r][col]) > math.Abs(a[pivot][col]) {
				pivot = r
			}
		}
		if math.Abs(a[pivot][col]) < 1e-9 {
			return fit{}, errors.New("the points don't tell the terms apart")
		}
		a[col], a[pivot] = a[pivot], a[col]
		for r := range n {
			if r == col {
				continue
			}
			factor := a[r][col] / a[col][col]
			for c := col; c <= n; c++ {
				a[r][c] -= factor * a[col][c]
			}
		}
	}
	result := fit{coefficients: make([]float64, n)}
	for i := range n {
		result.coefficients[i] = a[i][n] / a[i][i]
	}
	for _, p := range points {
		predicted := result.coefficients[0]
		for i, x := range p.x {
			predicted += result.coefficients[i+1] * x
		}
		result.largestResidual = max(result.largestResidual, math.Abs(p.y[0]-predicted))
	}
	return result, nil
}

// reachedAt returns the first whole count at which intercept + slope x count reaches limit: a projection along the
// fitted line, which holds only as far as the bytes keep growing as they did in the load.
func reachedAt(intercept, slope, limit float64) float64 {
	if slope <= 0 {
		return math.Inf(1)
	}
	// A count that reaches the limit exactly isn't pushed to the next one by the rounding of the division.
	return math.Ceil((limit-intercept)/slope - 1e-9)
}
