"""tests/test_models.py — Unit tests for ids/models.py.

Covers:
- AttackType and Severity enum values
- Alert and SuspiciousIP dataclass field types
- severity_for_alert for all attack types and boundary conditions
"""

import pytest

from ids.models import Alert, AttackType, Severity, SuspiciousIP, severity_for_alert


# ---------------------------------------------------------------------------
# AttackType enum
# ---------------------------------------------------------------------------


class TestAttackTypeEnum:
    def test_has_port_scan(self):
        assert AttackType.PORT_SCAN.value == "PORT_SCAN"

    def test_has_brute_force(self):
        assert AttackType.BRUTE_FORCE.value == "BRUTE_FORCE"

    def test_has_dos(self):
        assert AttackType.DOS.value == "DOS"

    def test_exactly_three_members(self):
        assert len(AttackType) == 3

    def test_is_string_enum(self):
        # AttackType inherits from str so it can be used directly as a string
        assert isinstance(AttackType.PORT_SCAN, str)
        assert AttackType.PORT_SCAN == "PORT_SCAN"


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------


class TestSeverityEnum:
    def test_has_low(self):
        assert Severity.LOW.value == "LOW"

    def test_has_medium(self):
        assert Severity.MEDIUM.value == "MEDIUM"

    def test_has_high(self):
        assert Severity.HIGH.value == "HIGH"

    def test_has_critical(self):
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_exactly_four_members(self):
        assert len(Severity) == 4

    def test_is_string_enum(self):
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "HIGH"


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------


class TestAlertDataclass:
    def _make_alert(self, **overrides):
        defaults = dict(
            id="550e8400-e29b-41d4-a716-446655440000",
            timestamp="2024-01-15T10:30:00.000000Z",
            src_ip="192.168.1.1",
            attack_type=AttackType.PORT_SCAN,
            severity=Severity.MEDIUM,
            metadata={"port_count": 25, "ports_sampled": [80, 443, 8080]},
        )
        defaults.update(overrides)
        return Alert(**defaults)

    def test_id_is_str(self):
        alert = self._make_alert()
        assert isinstance(alert.id, str)

    def test_timestamp_is_str(self):
        alert = self._make_alert()
        assert isinstance(alert.timestamp, str)

    def test_src_ip_is_str(self):
        alert = self._make_alert()
        assert isinstance(alert.src_ip, str)

    def test_attack_type_is_attack_type(self):
        alert = self._make_alert()
        assert isinstance(alert.attack_type, AttackType)

    def test_severity_is_severity(self):
        alert = self._make_alert()
        assert isinstance(alert.severity, Severity)

    def test_metadata_is_dict(self):
        alert = self._make_alert()
        assert isinstance(alert.metadata, dict)

    def test_metadata_defaults_to_empty_dict(self):
        # metadata has a default_factory so it should not be shared between instances
        alert = Alert(
            id="abc",
            timestamp="2024-01-15T10:30:00Z",
            src_ip="10.0.0.1",
            attack_type=AttackType.DOS,
            severity=Severity.HIGH,
        )
        assert alert.metadata == {}

    def test_metadata_default_not_shared(self):
        a1 = Alert(
            id="a1",
            timestamp="2024-01-15T10:30:00Z",
            src_ip="10.0.0.1",
            attack_type=AttackType.DOS,
            severity=Severity.HIGH,
        )
        a2 = Alert(
            id="a2",
            timestamp="2024-01-15T10:30:01Z",
            src_ip="10.0.0.2",
            attack_type=AttackType.DOS,
            severity=Severity.HIGH,
        )
        a1.metadata["key"] = "value"
        assert "key" not in a2.metadata

    def test_field_values_stored_correctly(self):
        alert = self._make_alert(src_ip="10.0.0.5", severity=Severity.CRITICAL)
        assert alert.src_ip == "10.0.0.5"
        assert alert.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# SuspiciousIP dataclass
# ---------------------------------------------------------------------------


class TestSuspiciousIPDataclass:
    def _make_suspicious_ip(self, **overrides):
        defaults = dict(
            ip_address="192.168.1.100",
            first_seen="2024-01-15T10:00:00.000000Z",
            last_seen="2024-01-15T10:30:00.000000Z",
            alert_count=5,
            attack_types=[AttackType.PORT_SCAN, AttackType.BRUTE_FORCE],
        )
        defaults.update(overrides)
        return SuspiciousIP(**defaults)

    def test_ip_address_is_str(self):
        sip = self._make_suspicious_ip()
        assert isinstance(sip.ip_address, str)

    def test_first_seen_is_str(self):
        sip = self._make_suspicious_ip()
        assert isinstance(sip.first_seen, str)

    def test_last_seen_is_str(self):
        sip = self._make_suspicious_ip()
        assert isinstance(sip.last_seen, str)

    def test_alert_count_is_int(self):
        sip = self._make_suspicious_ip()
        assert isinstance(sip.alert_count, int)

    def test_attack_types_is_list(self):
        sip = self._make_suspicious_ip()
        assert isinstance(sip.attack_types, list)

    def test_attack_types_elements_are_attack_type(self):
        sip = self._make_suspicious_ip()
        for at in sip.attack_types:
            assert isinstance(at, AttackType)

    def test_attack_types_defaults_to_empty_list(self):
        sip = SuspiciousIP(
            ip_address="1.2.3.4",
            first_seen="2024-01-15T10:00:00Z",
            last_seen="2024-01-15T10:00:00Z",
            alert_count=0,
        )
        assert sip.attack_types == []

    def test_attack_types_default_not_shared(self):
        s1 = SuspiciousIP(
            ip_address="1.2.3.4",
            first_seen="2024-01-15T10:00:00Z",
            last_seen="2024-01-15T10:00:00Z",
            alert_count=0,
        )
        s2 = SuspiciousIP(
            ip_address="5.6.7.8",
            first_seen="2024-01-15T10:00:00Z",
            last_seen="2024-01-15T10:00:00Z",
            alert_count=0,
        )
        s1.attack_types.append(AttackType.DOS)
        assert AttackType.DOS not in s2.attack_types


# ---------------------------------------------------------------------------
# severity_for_alert — PORT_SCAN
# ---------------------------------------------------------------------------


class TestSeverityForAlertPortScan:
    def test_port_count_below_50_is_medium(self):
        assert severity_for_alert(AttackType.PORT_SCAN, port_count=1) == Severity.MEDIUM

    def test_port_count_49_is_medium(self):
        assert severity_for_alert(AttackType.PORT_SCAN, port_count=49) == Severity.MEDIUM

    def test_port_count_50_is_high(self):
        # boundary: exactly 50 → HIGH
        assert severity_for_alert(AttackType.PORT_SCAN, port_count=50) == Severity.HIGH

    def test_port_count_above_50_is_high(self):
        assert severity_for_alert(AttackType.PORT_SCAN, port_count=100) == Severity.HIGH

    def test_missing_port_count_raises(self):
        with pytest.raises(KeyError):
            severity_for_alert(AttackType.PORT_SCAN)


# ---------------------------------------------------------------------------
# severity_for_alert — BRUTE_FORCE
# ---------------------------------------------------------------------------


class TestSeverityForAlertBruteForce:
    def test_attempt_count_below_50_is_high(self):
        assert severity_for_alert(AttackType.BRUTE_FORCE, attempt_count=1) == Severity.HIGH

    def test_attempt_count_49_is_high(self):
        assert severity_for_alert(AttackType.BRUTE_FORCE, attempt_count=49) == Severity.HIGH

    def test_attempt_count_50_is_critical(self):
        # boundary: exactly 50 → CRITICAL
        assert severity_for_alert(AttackType.BRUTE_FORCE, attempt_count=50) == Severity.CRITICAL

    def test_attempt_count_above_50_is_critical(self):
        assert severity_for_alert(AttackType.BRUTE_FORCE, attempt_count=200) == Severity.CRITICAL

    def test_missing_attempt_count_raises(self):
        with pytest.raises(KeyError):
            severity_for_alert(AttackType.BRUTE_FORCE)


# ---------------------------------------------------------------------------
# severity_for_alert — DOS
# ---------------------------------------------------------------------------


class TestSeverityForAlertDoS:
    def test_packet_rate_below_500_is_high(self):
        assert severity_for_alert(AttackType.DOS, packet_rate=1.0) == Severity.HIGH

    def test_packet_rate_499_is_high(self):
        assert severity_for_alert(AttackType.DOS, packet_rate=499.9) == Severity.HIGH

    def test_packet_rate_500_is_critical(self):
        # boundary: exactly 500 → CRITICAL
        assert severity_for_alert(AttackType.DOS, packet_rate=500.0) == Severity.CRITICAL

    def test_packet_rate_above_500_is_critical(self):
        assert severity_for_alert(AttackType.DOS, packet_rate=1000.0) == Severity.CRITICAL

    def test_missing_packet_rate_raises(self):
        with pytest.raises(KeyError):
            severity_for_alert(AttackType.DOS)


# ---------------------------------------------------------------------------
# severity_for_alert — unknown attack type
# ---------------------------------------------------------------------------


class TestSeverityForAlertUnknown:
    def test_unknown_attack_type_raises_value_error(self):
        with pytest.raises(ValueError, match="Unrecognised attack_type"):
            severity_for_alert("UNKNOWN_TYPE")  # type: ignore[arg-type]
