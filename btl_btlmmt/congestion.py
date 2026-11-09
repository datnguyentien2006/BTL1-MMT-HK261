"""CUBIC-style congestion avoidance for the custom UDP transport.

Packet units; connection-wide cwnd, pacing, RFC 6298-style RTT estimator and
Karn sampling. This is not a complete TCP/RFC 9438 implementation (no ECN,
HyStart++, SACK fast recovery or spurious-loss undo).
"""


class CubicController:
    C = 0.4
    BETA = 0.7

    def __init__(self, now, initial_rto=0.25, initial_window=4, maximum=256):
        self.cwnd = float(initial_window)
        self.maximum = maximum
        self.ssthresh = 32.0
        self.w_max = self.cwnd
        self.epoch = None
        self.srtt = None
        self.rttvar = 0.0
        self.rto = initial_rto
        self.minimum_rto = min(initial_rto, 0.1)
        self.tokens = self.cwnd
        self.last_pace = now
        self.recovery_until = now
        self.loss_events = 0
        self.epoch_k = 0.0

    def on_ack(self, now, sample=None):
        if sample is not None:
            sample = max(sample, 0.001)
            if self.srtt is None:
                self.srtt, self.rttvar = sample, sample / 2
            else:
                self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
                self.srtt = 0.875 * self.srtt + 0.125 * sample
            self.rto = min(3.0, max(self.minimum_rto, self.srtt + 4 * self.rttvar))
        if now < self.recovery_until:
            return
        if self.cwnd < self.ssthresh:
            self.cwnd += 1
        else:
            if self.epoch is None:
                self.epoch = now
                self.w_max = max(self.w_max, self.cwnd)
                self.epoch_k = (max(0.0, self.w_max - self.cwnd) / self.C) ** (1 / 3)
            elapsed = now - self.epoch
            rtt = max(self.srtt or 0.1, 0.001)
            # K stays fixed for this epoch, based on the reduction point.
            cubic_target = self.C * (elapsed + rtt - self.epoch_k) ** 3 + self.w_max
            reno_target = self.w_max * self.BETA + (3 * (1 - self.BETA) / (1 + self.BETA)) * elapsed / rtt
            target = max(cubic_target, reno_target)
            self.cwnd += min(1.0, max(0.0, target - self.cwnd) / self.cwnd)
        self.cwnd = min(float(self.maximum), self.cwnd)

    def on_timeout(self, now):
        if now < self.recovery_until:
            return
        previous = self.cwnd
        self.w_max = previous * (1 + self.BETA) / 2 if previous < self.w_max else previous
        self.ssthresh = max(2.0, previous * self.BETA)
        self.cwnd = 1.0
        self.epoch = None
        self.tokens = min(self.tokens, 1.0)
        self.recovery_until = now + self.rto
        self.loss_events += 1

    def permit(self, now):
        elapsed = max(0.0, now - self.last_pace)
        self.last_pace = now
        interval = max(self.srtt or 0.1, 0.01)
        self.tokens = min(self.cwnd, self.tokens + elapsed * self.cwnd / interval)
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True
