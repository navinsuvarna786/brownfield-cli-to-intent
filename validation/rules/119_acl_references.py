class Rule:
    id = "119"
    description = "Verify ACL names referenced in SNMP configuration are defined in the ACL table"
    severity = "HIGH"

    @classmethod
    def _defined_acl_names(cls, data):
        names = set()
        for acl in data.get("acls", []):
            if isinstance(acl, dict) and acl.get("name"):
                names.add(str(acl["name"]))
        return names

    @classmethod
    def match(cls, data):
        results = []
        try:
            snmp = data.get("snmp_config")
            if not isinstance(snmp, dict):
                return results

            acl_refs = {
                "snmp_config.acl_ro": snmp.get("acl_ro"),
                "snmp_config.acl_rw": snmp.get("acl_rw"),
            }

            # Only run referential checks when there are ACLs to compare against
            defined = cls._defined_acl_names(data)
            if not defined:
                return results

            for field, acl_name in acl_refs.items():
                if not acl_name:
                    continue
                acl_name_str = str(acl_name).strip()
                if acl_name_str and acl_name_str not in defined:
                    results.append(
                        f"{field}: references ACL '{acl_name_str}' "
                        f"which is not defined in the ACL table"
                    )
        except KeyError as e:
            print(f"KeyError: {e}")
        return results
