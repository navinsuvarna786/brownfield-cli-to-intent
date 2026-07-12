class Rule:
    id = "121"
    description = (
        "System completeness: dns_servers, ntp_servers, stp_mode, logging_hosts, "
        "and errdisable_config.causes must each have at least one entry"
    )
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []

        # dns_servers
        dns = data.get("dns_servers")
        if not dns or (isinstance(dns, list) and len(dns) == 0):
            results.append(
                "dns_servers is missing or empty - add at least one DNS server IP, "
                "use '[need_input]' as a placeholder if unknown"
            )

        # ntp_servers
        ntp = data.get("ntp_servers")
        if not ntp or (isinstance(ntp, list) and len(ntp) == 0):
            results.append(
                "ntp_servers is missing or empty - add at least one NTP server IP, "
                "use '[need_input]' as a placeholder if unknown"
            )

        # stp_mode
        stp = data.get("stp_mode")
        if not stp or str(stp).strip() == "":
            results.append(
                "stp_mode is missing or empty - set to 'rapid-pvst' or '[need_input]' as a placeholder"
            )

        # logging_hosts
        lhosts = data.get("logging_hosts")
        if not lhosts or (isinstance(lhosts, list) and len(lhosts) == 0):
            results.append(
                "logging_hosts is missing or empty - add at least one syslog server IP, "
                "use '[need_input]' as a placeholder if unknown"
            )

        # errdisable_config.causes
        errdis = data.get("errdisable_config")
        has_causes = False
        if isinstance(errdis, dict):
            causes = errdis.get("causes", [])
            if isinstance(causes, list) and len(causes) > 0:
                has_causes = True
        if not has_causes:
            results.append(
                "errdisable_config.causes is missing or empty - add at least one errdisable cause, "
                "use '[need_input]' as a placeholder if unknown"
            )

        return results
