//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"strings"
	"testing"
	"time"
)

// scriptedDatapathStatSource replays a fixed sequence of readings, one per
// report() call, so the reporter's arithmetic can be exercised with no BPF, no
// root and no kernel. A nil entry stands for a tick on which every source
// failed to read.
type scriptedDatapathStatSource struct {
	script [][]datapathStatReading
	tick   int
}

func (s *scriptedDatapathStatSource) readDatapathStats() []datapathStatReading {
	if s.tick >= len(s.script) {
		return nil
	}
	readings := s.script[s.tick]
	s.tick++
	return readings
}

type capturedDatapathReport struct {
	level   datapathReportLevel
	message string
}

// runDatapathReportScript drives one report() per scripted tick and returns
// only the lines that were actually emitted.
func runDatapathReportScript(script [][]datapathStatReading) []capturedDatapathReport {
	var captured []capturedDatapathReport
	reporter := newDatapathReporter(
		&scriptedDatapathStatSource{script: script},
		func(level datapathReportLevel, message string) {
			captured = append(captured, capturedDatapathReport{level: level, message: message})
		},
	)
	for range script {
		reporter.report()
	}
	return captured
}

func reading(stat datapathStat, total uint64) datapathStatReading {
	return datapathStatReading{stat: stat, total: total}
}

// TestDatapathReportMeasuresTheFirstIntervalFromZero covers the first of the
// three rules together with the baseline the deltas are taken against. Every
// map these counters live in is created with its backend and released on close
// -- nothing in this tree pins one -- so a fresh reporter starts against a
// kernel whose counters are genuinely zero, and the first interval is a real
// interval that must be reported. Adopting the first reading as the baseline
// instead would discard a whole interval of a condition that was already
// happening at startup, which is the exact case this report exists to catch.
// After that first line the rule holds as before: what is printed is the delta
// since the previous line, with the lifetime total riding alongside it.
func TestDatapathReportMeasuresTheFirstIntervalFromZero(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		{reading(datapathStatTCListenerSocketMissing, 40)},
		{reading(datapathStatTCListenerSocketMissing, 40)},
		{reading(datapathStatTCListenerSocketMissing, 43)},
	})
	if len(captured) != 2 {
		t.Fatalf("emitted %d lines, want 2 (first interval, quiet, delta): %+v", len(captured), captured)
	}
	if !strings.Contains(captured[0].message, "tc_listener_socket_missing=40 (total 40)") {
		t.Fatalf("the first interval was not measured from zero: %q", captured[0].message)
	}
	if !strings.Contains(captured[1].message, "tc_listener_socket_missing=3 (total 43)") {
		t.Fatalf("line does not report the delta next to the lifetime total: %q", captured[1].message)
	}
}

// TestDatapathReportSuppressesUnmovedIntervals covers the second rule: a
// datapath that is degraded but not degrading further must stop costing a line
// per tick, or a real signal gets trained out of whoever reads the log.
//
// The script is also the self-healing case, which is the other half of why the
// baseline is zero rather than the first reading: a listener that never entered
// the SOCKMAP counts from the first packet, before the reporter's first tick,
// and if it rebinds the counter never moves again. Exactly one line is the only
// right answer for that -- priming on the first reading would log nothing at
// all, and re-reporting a standing total would log it forever.
func TestDatapathReportSuppressesUnmovedIntervals(t *testing.T) {
	stuck := []datapathStatReading{
		reading(datapathStatTCListenerSocketMissing, 40),
		reading(datapathStatSharedRewriteFailure, 7),
	}
	captured := runDatapathReportScript([][]datapathStatReading{stuck, stuck, stuck, stuck, stuck})
	if len(captured) != 1 {
		t.Fatalf("a condition that happened once and stopped emitted %d lines, want 1: %+v",
			len(captured), captured)
	}
	for _, field := range []string{"tc_listener_socket_missing=40 (total 40)", "shared_rewrite_failure=7 (total 7)"} {
		if !strings.Contains(captured[0].message, field) {
			t.Fatalf("the one reported interval is missing %q: %q", field, captured[0].message)
		}
	}
}

// TestDatapathReportOmitsUnmovedCountersFromAMovedInterval proves the
// suppression is per counter and not only per line: a counter that is stuck at
// a large lifetime total must not be re-listed just because another counter
// moved.
func TestDatapathReportOmitsUnmovedCountersFromAMovedInterval(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		{
			reading(datapathStatTCListenerSocketMissing, 50),
			reading(datapathStatSharedRewriteFailure, 4),
		},
		{
			reading(datapathStatTCListenerSocketMissing, 50),
			reading(datapathStatSharedRewriteFailure, 6),
		},
	})
	if len(captured) != 2 {
		t.Fatalf("emitted %d lines, want 2: %+v", len(captured), captured)
	}
	if strings.Contains(captured[1].message, "tc_listener_socket_missing") {
		t.Fatalf("a counter that did not move was reported: %q", captured[1].message)
	}
	if !strings.Contains(captured[1].message, "shared_rewrite_failure=2") {
		t.Fatalf("moved counter missing from the line: %q", captured[1].message)
	}
}

// TestDatapathReportRebaselinesWhenACounterGoesBackwards covers the reload
// case. These counters live in maps that can be replaced underneath the
// reporter, and the per-CPU sum can drop, so a lower total is not a delta at
// all -- subtracting would underflow uint64 into an enormous fake count and
// escalate the line to a warning on a datapath that is fine.
func TestDatapathReportRebaselinesWhenACounterGoesBackwards(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		{reading(datapathStatSharedTokenReservationFailure, 20)},
		// The map behind the counter was replaced: the total restarts low.
		{reading(datapathStatSharedTokenReservationFailure, 2)},
		// Measured from the new baseline, not from the pre-reload total.
		{reading(datapathStatSharedTokenReservationFailure, 6)},
	})
	if len(captured) != 2 {
		t.Fatalf("emitted %d lines, want 2 (the reset itself must be silent): %+v", len(captured), captured)
	}
	if captured[1].level != datapathReportInfo {
		t.Fatalf("level = %v, want info; a reset must not be read as a huge delta", captured[1].level)
	}
	if !strings.Contains(captured[1].message, "shared_token_reservation_failure=4 (total 6)") {
		t.Fatalf("delta not measured from the post-reset baseline: %q", captured[1].message)
	}
}

// TestDatapathReportWrapAroundIsNotADelta is the same defence at the extreme
// end: a counter at the top of its range that wraps to a small value must
// re-baseline rather than produce a near-2^64 delta. A baseline is established
// near the top first, because with a zero baseline a first reading of 2^64-6 is
// an ordinary (if absurd) delta and would prove nothing about the wrap; the
// third tick is the wrap, and it is the one that has to stay silent.
func TestDatapathReportWrapAroundIsNotADelta(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		{reading(datapathStatTCSKAssignFailed, ^uint64(0)-5)},
		{reading(datapathStatTCSKAssignFailed, ^uint64(0))},
		// The counter wrapped past the top of uint64.
		{reading(datapathStatTCSKAssignFailed, 1)},
		// Measured from the post-wrap baseline, not from 2^64-1.
		{reading(datapathStatTCSKAssignFailed, 4)},
	})
	if len(captured) != 3 {
		t.Fatalf("emitted %d lines, want 3 (the wrap itself must be silent): %+v", len(captured), captured)
	}
	if captured[1].level != datapathReportInfo ||
		!strings.Contains(captured[1].message, "tc_sk_assign_failed=5 (total 18446744073709551615)") {
		t.Fatalf("the interval leading up to the wrap was misreported: %+v", captured[1])
	}
	if captured[2].level != datapathReportInfo ||
		!strings.Contains(captured[2].message, "tc_sk_assign_failed=3 (total 4)") {
		t.Fatalf("delta not measured from the post-wrap baseline: %+v", captured[2])
	}
}

// TestDatapathReportEscalatesPastTheSustainedThreshold covers the third rule.
// Below the threshold the interval is a plausible race with a reload; above it
// the datapath is losing traffic continuously and the line must be a warning.
func TestDatapathReportEscalatesPastTheSustainedThreshold(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		{reading(datapathStatTCAssignmentUpdateFailed, datapathHeavySustainedDelta)},
		{reading(datapathStatTCAssignmentUpdateFailed, 2*datapathHeavySustainedDelta+1)},
	})
	if len(captured) != 2 {
		t.Fatalf("emitted %d lines, want 2: %+v", len(captured), captured)
	}
	if captured[0].level != datapathReportInfo {
		t.Fatalf("a delta exactly at the threshold escalated: level = %v", captured[0].level)
	}
	if captured[1].level != datapathReportWarn {
		t.Fatalf("a delta past the threshold did not escalate: level = %v", captured[1].level)
	}
}

// TestDatapathReportGradesEveryCounterAsEscalatableLostTraffic pins the grading
// half of every descriptor row, which the arithmetic tests above only exercise
// for the one counter each of them happens to script. Every row left in the
// table describes a packet that was dropped or that escaped this data plane
// unproxied, so none of them may sit below info, and none of them may be
// exempt from escalation: a heavy of 0 would mean a datapath losing traffic
// continuously on that counter could never raise more than an info line. This
// is the invariant that a row added at debug, or without a threshold, has to be
// a deliberate decision rather than an oversight.
func TestDatapathReportGradesEveryCounterAsEscalatableLostTraffic(t *testing.T) {
	for stat := datapathStat(0); stat < datapathStatCount; stat++ {
		descriptor := datapathStatDescriptors[stat]
		t.Run(descriptor.name, func(t *testing.T) {
			if descriptor.level < datapathReportInfo {
				t.Fatalf("level = %v, want at least info: every row here is lost traffic", descriptor.level)
			}
			if descriptor.heavy == 0 {
				t.Fatalf("heavy = 0: this counter could never escalate past info")
			}
			captured := runDatapathReportScript([][]datapathStatReading{
				{reading(stat, 1)},
				{reading(stat, 1+descriptor.heavy+1)},
			})
			if len(captured) != 2 {
				t.Fatalf("emitted %d lines, want 2: %+v", len(captured), captured)
			}
			if captured[0].level != datapathReportInfo {
				t.Fatalf("a single event graded %v, want info", captured[0].level)
			}
			if captured[1].level != datapathReportWarn {
				t.Fatalf("a delta past heavy graded %v, want warn", captured[1].level)
			}
		})
	}
}

// TestDatapathReportTakesTheMostSevereLevel proves the line's level is the
// maximum over the counters in it and not merely the last one classified: a
// counter whose interval is a plausible race must not grade down a line that
// another counter is losing traffic continuously in. Both orders are scripted
// because either mistake -- taking the last field's level, or the first's --
// passes with one of them.
func TestDatapathReportTakesTheMostSevereLevel(t *testing.T) {
	light := reading(datapathStatSharedRewriteFailure, 3)
	heavy := reading(datapathStatTCListenerSocketMissing, datapathHeavySustainedDelta+1)
	for _, test := range []struct {
		name     string
		readings []datapathStatReading
	}{
		{name: "heavy first", readings: []datapathStatReading{heavy, light}},
		{name: "heavy last", readings: []datapathStatReading{light, heavy}},
	} {
		t.Run(test.name, func(t *testing.T) {
			captured := runDatapathReportScript([][]datapathStatReading{test.readings})
			if len(captured) != 1 {
				t.Fatalf("emitted %d lines, want 1: %+v", len(captured), captured)
			}
			if captured[0].level != datapathReportWarn {
				t.Fatalf("level = %v, want warn", captured[0].level)
			}
			for _, field := range []string{"shared_rewrite_failure=3", "tc_listener_socket_missing=101"} {
				if !strings.Contains(captured[0].message, field) {
					t.Fatalf("line is missing %q: %q", field, captured[0].message)
				}
			}
		})
	}
}

// TestDatapathReportCarriesAFailedReadIntoTheNextInterval covers a source that
// could not read a counter on one tick. Skipping it must not be mistaken for a
// reset or for movement, and the events that happened across both intervals
// must still be reported once the read succeeds again.
func TestDatapathReportCarriesAFailedReadIntoTheNextInterval(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		nil, // nothing was readable yet
		{reading(datapathStatSharedFakeIPICMPRewriteFailure, 10)},
		nil, // every read failed this tick
		{reading(datapathStatSharedFakeIPICMPRewriteFailure, 13)},
	})
	if len(captured) != 2 {
		t.Fatalf("emitted %d lines, want 2 (the two failed reads must be silent): %+v", len(captured), captured)
	}
	if !strings.Contains(captured[0].message, "shared_fakeip_icmp_rewrite_failure=10 (total 10)") {
		t.Fatalf("a read that failed before anything was ever read disturbed the baseline: %q", captured[0].message)
	}
	if !strings.Contains(captured[1].message, "shared_fakeip_icmp_rewrite_failure=3 (total 13)") {
		t.Fatalf("the skipped interval's events were lost or re-counted: %q", captured[1].message)
	}
}

// TestDatapathReportMeasuresALateCounterFromZeroToo covers a source that starts
// reporting a counter partway through the run -- a data plane that was rebuilt,
// or a feature switched on. Its map was created with that backend, so its total
// is a lifetime figure over a lifetime that began after the reporter did, and
// zero is still the honest baseline for it: the whole of its first reading
// happened on this run and belongs in a line.
func TestDatapathReportMeasuresALateCounterFromZeroToo(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		{reading(datapathStatTCListenerSocketMissing, 1)},
		{reading(datapathStatTCListenerSocketMissing, 1), reading(datapathStatSharedRewriteFailure, 7)},
		{reading(datapathStatTCListenerSocketMissing, 1), reading(datapathStatSharedRewriteFailure, 8)},
	})
	if len(captured) != 3 {
		t.Fatalf("emitted %d lines, want 3: %+v", len(captured), captured)
	}
	if !strings.Contains(captured[1].message, "shared_rewrite_failure=7 (total 7)") {
		t.Fatalf("a counter that appeared mid-run was not measured from zero: %q", captured[1].message)
	}
	if strings.Contains(captured[1].message, "tc_listener_socket_missing") {
		t.Fatalf("the long-running counter did not move and was reported anyway: %q", captured[1].message)
	}
	if !strings.Contains(captured[2].message, "shared_rewrite_failure=1 (total 8)") {
		t.Fatalf("the late counter's own baseline did not advance: %q", captured[2].message)
	}
}

// TestDatapathReportIgnoresOutOfRangeStats guards the indexed baseline array
// against a source that reports an identity this build does not know.
func TestDatapathReportIgnoresOutOfRangeStats(t *testing.T) {
	captured := runDatapathReportScript([][]datapathStatReading{
		{reading(datapathStatCount, 1), reading(-1, 1)},
		{reading(datapathStatCount, 500), reading(-1, 500)},
	})
	if len(captured) != 0 {
		t.Fatalf("an unknown counter was reported: %+v", captured)
	}
}

// TestDatapathStatDescriptorsAreComplete stops a new datapathStat from being
// added without a row, which would otherwise be reported as an empty name.
func TestDatapathStatDescriptorsAreComplete(t *testing.T) {
	for stat := datapathStat(0); stat < datapathStatCount; stat++ {
		if datapathStatDescriptors[stat].name == "" {
			t.Fatalf("datapathStat %d has no descriptor", stat)
		}
	}
}

// risingDatapathStatSource advances one counter by one on every read, so a
// running loop produces a line per tick.
type risingDatapathStatSource struct{ total uint64 }

func (s *risingDatapathStatSource) readDatapathStats() []datapathStatReading {
	s.total++
	return []datapathStatReading{reading(datapathStatTCListenerSocketMissing, s.total)}
}

// TestDatapathReportLoopTicksAndStops covers the cadence itself: the loop
// reports once per interval and returns as soon as its context is cancelled.
func TestDatapathReportLoopTicksAndStops(t *testing.T) {
	lines := make(chan capturedDatapathReport, 16)
	reporter := newDatapathReporter(&risingDatapathStatSource{}, func(level datapathReportLevel, message string) {
		select {
		case lines <- capturedDatapathReport{level: level, message: message}:
		default:
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDatapathReports(ctx, time.Millisecond, reporter)
	}()
	select {
	case line := <-lines:
		if !strings.Contains(line.message, "tc_listener_socket_missing=1") {
			t.Fatalf("unexpected line: %q", line.message)
		}
	case <-time.After(10 * time.Second):
		cancel()
		<-done
		t.Fatal("reporter loop never produced a line")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reporter loop did not stop on cancel")
	}
}

// TestDatapathReporterStopsOnClose mirrors TestUDPJanitorStopsOnClose: the
// report owns a goroutine, so Close must actually join it rather than leaving
// it reading maps that are about to be released. The quiet source keeps the
// global logger out of this test.
func TestDatapathReporterStopsOnClose(t *testing.T) {
	i := &Inbound{}
	i.startDatapathReportLoop(&scriptedDatapathStatSource{}, time.Millisecond)
	done := i.datapathReportDone
	i.stopDatapathReporter()
	select {
	case <-done:
	default:
		t.Fatal("reporter still running")
	}
	if i.datapathReportCancel != nil || i.datapathReportDone != nil {
		t.Fatal("reporter state not cleared")
	}
	// Idempotent: Close runs under closeOnce, but a second stop must not panic
	// on the nil channel it just left behind.
	i.stopDatapathReporter()
}

// An inbound with no prepared data plane must not pay for a report goroutine.
func TestDatapathReporterSkippedWithoutAStatSource(t *testing.T) {
	i := &Inbound{}
	i.startDatapathReporter()
	if i.datapathReportCancel != nil {
		t.Fatal("reporter started with nothing to read")
	}
}

// The gate decides whether the reporter runs at all, and an inbound with both
// sources nil cannot tell && from ||: a TC-only inbound is the common case, so
// flipping the operator would silently stop reporting for most deployments
// while an all-nil test still passed.
func TestDatapathReporterGateFollowsTheSourcesItWouldRead(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(*Inbound)
		want  bool
	}{
		{name: "nothing to read", build: func(*Inbound) {}, want: false},
		// tcBackend() returns tcDataPlane.backend, so a tcDataPlane with no
		// backend in it is still nothing to read -- the data plane is being built
		// or has been torn down. Only a non-nil backend counts.
		{name: "TC data plane without a backend", build: func(i *Inbound) {
			i.tcDataPlane = &tcDataPlane{}
		}, want: false},
		{name: "TC only", build: func(i *Inbound) {
			i.tcDataPlane = &tcDataPlane{backend: &ECommon.TCBackend{}}
		}, want: true},
		{name: "shared rewrite only", build: func(i *Inbound) { i.sharedRewrite = &sharedRewrite{} }, want: true},
		{name: "cgroup only", build: func(i *Inbound) { i.cgroupBackend = &ECommon.CgroupBackend{} }, want: true},
		{name: "both", build: func(i *Inbound) {
			i.tcDataPlane = &tcDataPlane{backend: &ECommon.TCBackend{}}
			i.sharedRewrite = &sharedRewrite{}
		}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			i := &Inbound{}
			test.build(i)
			if got := i.hasDatapathStatSource(); got != test.want {
				t.Fatalf("hasDatapathStatSource = %v, want %v", got, test.want)
			}
		})
	}
}

// Every reporter test injects a scripted source, so the one place that pairs a
// TCStats field with the identity it is reported under is otherwise never
// executed: swapping two adjacent lines there would tell an operator to go
// looking at the listeners when the assignment tables are what failed.
func TestDatapathStatReadingsLabelEachTCCounterAsItself(t *testing.T) {
	readings := tcDatapathStatReadings(ECommon.TCStats{
		ListenerSocketMissing:  1,
		SKAssignFailed:         2,
		AssignmentUpdateFailed: 3,
		DeliveryRewriteFailed:  4,
	})
	got := make(map[datapathStat]uint64, len(readings))
	for _, reading := range readings {
		got[reading.stat] = reading.total
	}
	for stat, want := range map[datapathStat]uint64{
		datapathStatTCListenerSocketMissing:  1,
		datapathStatTCSKAssignFailed:         2,
		datapathStatTCAssignmentUpdateFailed: 3,
		datapathStatTCDeliveryRewriteFailed:  4,
	} {
		if got[stat] != want {
			t.Fatalf("%s reported %d, want %d -- the field and its identity disagree",
				datapathStatDescriptors[stat].name, got[stat], want)
		}
	}
	if len(readings) != 4 {
		t.Fatalf("got %d TC readings, want 4", len(readings))
	}
}
