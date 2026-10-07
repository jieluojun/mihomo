//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"fmt"
	"strings"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/log"
)

// This file is the operator-visible outlet of the kernel's degradation
// counters. Three maps already count them -- tc.bpf.c's tc_stats,
// shared_network.bpf.c's shared_stats, fakeip_icmp.bpf.c's fakeip_icmp_stats --
// and until now nothing put any of them in front of a human on a cadence:
// shared_stats was read only to decide when the flow janitor should sweep
// harder, and the other two were read only by tests. docs/internals.md says
// what that costs, in the fork's own words: these degradation paths all "work,
// just without headroom", and from outside they look identical to a healthy
// datapath. That is why the 断流 bug took as long as it did to find.
//
// Three properties keep the report honest. Each is a bug that was found by
// writing the naive version first, not a preference:
//
//   - It reports the DELTA since the previous line, never the lifetime total.
//     A total only ever climbs for as long as a backend lives, so a report keyed
//     on "counter > 0" becomes permanently true after a single event ever
//     observed and re-alerts forever, presenting a historical count as pressure
//     happening now. A threshold compared against the lifetime total is the same
//     bug wearing a bigger number.
//   - It emits ONLY when something moved. Rule one alone is not enough: a
//     datapath that never recovers would otherwise cost a line every tick for
//     as long as the process runs, which is how a real signal gets trained out
//     of an operator. A condition that stops, stops being reported.
//   - It escalates past a per-interval threshold. A handful of events is a race
//     with a reload or a listener restart and belongs at info; a rate that
//     cannot be a race is a condition, and belongs at warning.

const (
	// datapathReportInterval paces the report. The counters describe conditions
	// that last as long as the flows they affect, so a fast cadence would just
	// trade a per-event log for a per-tick one; 30s keeps a burst's magnitude
	// visible while capping a permanently degraded datapath at 120 lines/hour.
	// It is also the denominator of every delta printed, so it has to be fixed:
	// see startDatapathReporter for why this is a ticker of its own rather than
	// a hook on an existing loop.
	datapathReportInterval = 30 * time.Second

	// datapathHeavySustainedDelta is the per-interval count above which a
	// degradation stops being a transient. Over datapathReportInterval it works
	// out to ~3.3 events/second sustained. The benign explanations are all
	// bounded and small: a flow that raced a reload retries a TCP handshake
	// about three times before giving up, a UDP client re-sends a few datagrams,
	// a listener restart affects the flows in flight during the restart. None of
	// them can hold 3.3/s across a whole interval, so above this the datapath is
	// not losing an occasional packet, it is losing traffic continuously -- and
	// the line is raised from info to a warning.
	datapathHeavySustainedDelta = 100
)

// datapathReportLevel is the report's own severity, ordered least severe first
// so classification can simply take the maximum: one heavy counter must be able
// to raise a line that a debug-level counter would otherwise have graded down.
// It maps onto exactly the three log functions used elsewhere in this package.
type datapathReportLevel int

const (
	datapathReportDebug datapathReportLevel = iota
	datapathReportInfo
	datapathReportWarn
)

// datapathStat identifies one counter across every source. The identity is what
// the baseline is keyed on, so two sources must never share one: when a local TC
// data plane and a shared packet-rewrite data plane are both running they each
// load their own fakeip_icmp object, and folding the two into one row would
// difference one object's total against the other's.
type datapathStat int

const (
	datapathStatTCListenerSocketMissing datapathStat = iota
	datapathStatTCSKAssignFailed
	datapathStatTCAssignmentUpdateFailed
	datapathStatTCDeliveryRewriteFailed
	datapathStatSharedTokenReservationFailure
	datapathStatSharedRewriteFailure
	datapathStatTCFakeIPICMPRewriteFailure
	datapathStatSharedFakeIPICMPRewriteFailure
	datapathStatCgroupUDPReleaseDrops
	datapathStatCount
)

// datapathStatDescriptor is how one counter's movement is graded. level is what
// the counter means on its own; heavy (0 = never escalates) raises the whole
// line to a warning when a single interval exceeds it. The name, the grading
// and the identity live in one row so the delta arithmetic, the classification
// and the emitted text cannot drift apart.
type datapathStatDescriptor struct {
	name  string
	level datapathReportLevel
	heavy uint64
}

// datapathStatDescriptors is indexed by datapathStat. Rows describe traffic
// loss or degraded cleanup, so info is the floor. heavy stays available for a row
// that repeats per packet on a static misconfiguration, which must not be able
// to raise a warning every interval forever.
var datapathStatDescriptors = [datapathStatCount]datapathStatDescriptor{
	datapathStatCgroupUDPReleaseDrops: {
		name: "cgroup_udp_release_drops", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatTCListenerSocketMissing: {
		name: "tc_listener_socket_missing", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatTCSKAssignFailed: {
		name: "tc_sk_assign_failed", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatTCAssignmentUpdateFailed: {
		name: "tc_assignment_update_failed", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatTCDeliveryRewriteFailed: {
		name: "tc_delivery_rewrite_failed", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatSharedTokenReservationFailure: {
		name: "shared_token_reservation_failure", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatSharedRewriteFailure: {
		name: "shared_rewrite_failure", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatTCFakeIPICMPRewriteFailure: {
		name: "tc_fakeip_icmp_rewrite_failure", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
	datapathStatSharedFakeIPICMPRewriteFailure: {
		name: "shared_fakeip_icmp_rewrite_failure", level: datapathReportInfo, heavy: datapathHeavySustainedDelta,
	},
}

// datapathStatReading is one counter's lifetime total as a source read it. A
// source omits any counter it could not read rather than reporting a zero:
// a zero is indistinguishable from a counter that never moved, and adopting it
// as a baseline would make the next successful read look like a huge delta.
type datapathStatReading struct {
	stat  datapathStat
	total uint64
}

// datapathStatSource is everything the reporter needs from the kernel. It is an
// interface so the delta arithmetic, the zero-delta suppression and the
// escalation are testable from a script of readings, with no BPF, no root and
// no kernel; inboundDatapathStatSource is the only real implementation.
type datapathStatSource interface {
	readDatapathStats() []datapathStatReading
}

// datapathReporter holds the counter values the last line consumed. The zero
// baseline is the real one -- these maps are created with their backend and are
// never pinned -- so a counter that first appears mid-run, from a data plane
// that was rebuilt or a feature that was switched on, is measured from zero as
// well, because its map is new too.
type datapathReporter struct {
	source   datapathStatSource
	emit     func(level datapathReportLevel, message string)
	baseline [datapathStatCount]uint64
}

func newDatapathReporter(source datapathStatSource, emit func(level datapathReportLevel, message string)) *datapathReporter {
	return &datapathReporter{source: source, emit: emit}
}

// report publishes one interval of datapath degradation, or nothing at all.
// Only called from the single reporter goroutine, so the baselines need no
// synchronisation of their own.
func (r *datapathReporter) report() {
	readings := r.source.readDatapathStats()
	level := datapathReportDebug
	moved := false
	fields := make([]string, 0, len(readings))
	for _, reading := range readings {
		if reading.stat < 0 || reading.stat >= datapathStatCount {
			continue
		}
		descriptor := &datapathStatDescriptors[reading.stat]
		// Every map this reads is created fresh with its backend and released on
		// close -- nothing here is pinned -- so a counter seen for the first
		// time started this run at zero, and zero is the honest baseline. That
		// holds for a backend rebuilt mid-run too: its map is new as well.
		// Adopting the first reading instead would discard a whole interval of a
		// condition that was already happening, which is the case this report
		// exists for: a listener that never entered the SOCKMAP counts from the
		// first packet, and if it self-heals inside one interval nothing would
		// ever be logged at all.
		base := r.baseline[reading.stat]
		// Consume unconditionally. Unlike a reporter that is polled faster than
		// it prints, this one owns its cadence and emits on every interval that
		// moved, so advancing the baseline here can never drop an interval that
		// was never reported: an interval that is not emitted is one whose delta
		// was zero, and consuming a zero delta changes nothing.
		r.baseline[reading.stat] = reading.total
		switch {
		case reading.total < base:
			// The counter went backwards: the map behind it was replaced, or the
			// per-CPU sum lost a CPU. Either way this interval is not comparable
			// with the baseline, and subtracting would underflow uint64 into a
			// spectacular fake delta. Re-baselined above; report nothing.
			continue
		}
		delta := reading.total - base
		if delta == 0 {
			continue
		}
		moved = true
		fieldLevel := descriptor.level
		if descriptor.heavy > 0 && delta > descriptor.heavy {
			fieldLevel = datapathReportWarn
		}
		if fieldLevel > level {
			level = fieldLevel
		}
		// The lifetime total rides along with every delta: the delta is what is
		// happening now, the total is how long it has been happening, and an
		// operator reading one line needs both.
		fields = append(fields, fmt.Sprintf("%s=%d (total %d)", descriptor.name, delta, reading.total))
	}
	if !moved {
		return
	}
	r.emit(level, fmt.Sprintf("%s; %s over the last %s",
		datapathReportHeadline(level), strings.Join(fields, ", "), datapathReportInterval))
}

// datapathReportHeadline explains a line at the level it carries. A counter
// name on its own does not say whether traffic is being dropped, is leaking
// past the proxy, or is merely unhandled by design, so the headline says which
// and what to look at.
func datapathReportHeadline(level datapathReportLevel) string {
	switch level {
	case datapathReportWarn:
		return "datapath is degrading continuously and traffic is being dropped or is escaping the proxy; " +
			"check that the transparent listeners are still bound on the configured port, that the delivery " +
			"interface is up, and that the flow and assignment tables are not exhausted"
	case datapathReportInfo:
		return "datapath degradation in this interval: packets were dropped or passed through unhandled; " +
			"a small count is usually a flow racing a reload or a listener restart, a count that keeps " +
			"coming back is not"
	default:
		return "datapath conditions with no per-event warning advanced in this interval; reported at debug " +
			"level because they are by-design fallthroughs rather than lost traffic"
	}
}

// logDatapathReport is the production emit hook. Tests substitute their own so
// nothing here depends on the global logger.
func logDatapathReport(level datapathReportLevel, message string) {
	switch level {
	case datapathReportWarn:
		log.Warnln("[EBPF] %s", message)
	case datapathReportInfo:
		log.Infoln("[EBPF] %s", message)
	default:
		log.Debugln("[EBPF] %s", message)
	}
}

// inboundDatapathStatSource reads the three kernel stat maps this fork keeps.
// A backend that is gone, or a map read that fails, contributes nothing rather
// than a zero -- see datapathStatReading. Nothing is logged for a failed read:
// the common cause is a backend closing underneath a tick, and a shutdown must
// not produce a warning.
type inboundDatapathStatSource struct {
	inbound *Inbound
}

func (s inboundDatapathStatSource) readDatapathStats() []datapathStatReading {
	readings := make([]datapathStatReading, 0, datapathStatCount)
	if backend := s.inbound.cgroupBackendInstance(); backend != nil {
		if drops, err := backend.UDPReleaseNotificationDrops(); err == nil {
			readings = append(readings, datapathStatReading{datapathStatCgroupUDPReleaseDrops, drops})
		}
	}
	if backend := s.inbound.tcBackend(); backend != nil {
		if stats, err := backend.TCStats(); err == nil {
			readings = append(readings, tcDatapathStatReadings(stats)...)
		}
		readings = appendFakeIPICMPReading(readings, datapathStatTCFakeIPICMPRewriteFailure,
			backend.FakeIPICMPEnabled(), backend.FakeIPICMPRewriteFailureCount)
	}
	// sharedRewrite is read without a lock, as the UDP janitor does: Close stops
	// and joins this reporter before it clears the field.
	if shared := s.inbound.sharedRewrite; shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil {
			if failures, err := backend.TokenReservationFailures(); err == nil {
				readings = append(readings, datapathStatReading{datapathStatSharedTokenReservationFailure, failures})
			}
			if failures, err := backend.RewriteFailures(); err == nil {
				readings = append(readings, datapathStatReading{datapathStatSharedRewriteFailure, failures})
			}
			readings = appendFakeIPICMPReading(readings, datapathStatSharedFakeIPICMPRewriteFailure,
				backend.FakeIPICMPEnabled(), backend.FakeIPICMPRewriteFailureCount)
		}
	}
	return readings
}

// appendFakeIPICMPReading reads one fakeip_icmp object's rewrite-failure
// counter, and only when that feature is on -- the object is not loaded
// otherwise and every read would fail. Of that map's three categories only this
// one is a degradation: a reply actually sent is a success, and a request
// deliberately passed through is by design (it is dominated by ordinary ICMP to
// non-FakeIP addresses), so neither belongs in a report about lost traffic. A
// rewrite that failed partway is different: the packet was already mutated, so
// it is dropped rather than passed on.
func appendFakeIPICMPReading(
	readings []datapathStatReading,
	stat datapathStat,
	enabled bool,
	count func() (uint64, error),
) []datapathStatReading {
	if !enabled {
		return readings
	}
	failures, err := count()
	if err != nil {
		return readings
	}
	return append(readings, datapathStatReading{stat, failures})
}

// startDatapathReporter runs the report on a ticker of its own.
//
// The two existing maintenance loops were both considered and neither fits.
// The UDP janitor only runs when UDP is enabled, so a TCP-only inbound would
// never report at all, and it deliberately drops to a one-second interval while
// it continues a large sweep -- which would make the report's pacing a function
// of table size. The interface-update loop is driven by netlink notifications
// and can fire repeatedly during an attach, with nothing but a ten-minute drift
// check otherwise. A delta is only meaningful against a known interval, and
// both of those would make the interval vary with something that has nothing to
// do with what is being measured. So the report owns its cadence, and pays for
// it with one goroutine that Close stops and joins exactly as it does the
// janitor's.
func (i *Inbound) startDatapathReporter() {
	if !i.hasDatapathStatSource() {
		// Nothing to read until a data plane has been prepared.
		return
	}
	i.startDatapathReportLoop(inboundDatapathStatSource{inbound: i}, datapathReportInterval)
}

// startDatapathReportLoop is the spawn, split from the gate above so the
// goroutine's start/stop can be exercised without a loaded data plane.
func (i *Inbound) startDatapathReportLoop(source datapathStatSource, interval time.Duration) {
	parent := i.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	i.datapathReportCancel = cancel
	i.datapathReportDone = done
	reporter := newDatapathReporter(source, logDatapathReport)
	go func() {
		defer close(done)
		runDatapathReports(ctx, interval, reporter)
	}()
}

func runDatapathReports(ctx context.Context, interval time.Duration, reporter *datapathReporter) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reporter.report()
		}
	}
}

func (i *Inbound) stopDatapathReporter() {
	if i.datapathReportCancel != nil {
		i.datapathReportCancel()
		<-i.datapathReportDone
		i.datapathReportCancel = nil
		i.datapathReportDone = nil
	}
}

// tcDatapathStatReadings pairs each TC counter with the identity it is reported
// under. Kept apart from the rest of the read so the pairing is reachable
// without a kernel: it is the one place a field and its label can be swapped,
// and a swap sends an operator after the wrong subsystem.
func tcDatapathStatReadings(stats ECommon.TCStats) []datapathStatReading {
	return []datapathStatReading{
		{datapathStatTCListenerSocketMissing, stats.ListenerSocketMissing},
		{datapathStatTCSKAssignFailed, stats.SKAssignFailed},
		{datapathStatTCAssignmentUpdateFailed, stats.AssignmentUpdateFailed},
		{datapathStatTCDeliveryRewriteFailed, stats.DeliveryRewriteFailed},
	}
}

// hasDatapathStatSource includes cgroup release-event drops as well as TC and
// rewrite failures. A backend without the optional event map omits that reading.
func (i *Inbound) hasDatapathStatSource() bool {
	return i.tcBackend() != nil || i.sharedRewrite != nil || i.cgroupBackendInstance() != nil
}
