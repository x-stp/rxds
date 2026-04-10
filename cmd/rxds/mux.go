// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package main

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
)

func runMux(ctx context.Context, userQ, cloudQ <-chan target, targets chan<- target, nTargets *atomic.Uint64, weight int, seed uint32, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(targets)

	w := weight
	if w < 0 {
		w = 0
	}
	rng := rand.New(rand.NewSource(int64(seed ^ 0x9e3779b9)))

	cloudOpen, userOpen := true, true
	send := func(t target) {
		select {
		case targets <- t:
			nTargets.Add(1)
		case <-ctx.Done():
		}
	}

	for cloudOpen || userOpen {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if cloudOpen && userOpen {
			if w > 0 && rng.Intn(w+1) < w {
				select {
				case t, ok := <-cloudQ:
					if !ok {
						cloudOpen = false
						continue
					}
					send(t)
					continue
				default:
				}
			}
			select {
			case t, ok := <-userQ:
				if !ok {
					userOpen = false
					continue
				}
				send(t)
				continue
			default:
			}
			select {
			case t, ok := <-cloudQ:
				if !ok {
					cloudOpen = false
				} else {
					send(t)
				}
			case t, ok := <-userQ:
				if !ok {
					userOpen = false
				} else {
					send(t)
				}
			case <-ctx.Done():
				return
			}
			continue
		}

		if cloudOpen {
			t, ok := <-cloudQ
			if !ok {
				cloudOpen = false
				continue
			}
			send(t)
			continue
		}
		t, ok := <-userQ
		if !ok {
			userOpen = false
			continue
		}
		send(t)
	}
}
