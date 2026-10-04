"""os_remove_join (CWE-22) - bad variant.

Generated benchmark file. The bad variant is the vulnerable form of this scenario.
"""
import os


def purge_report(report_id):
    os.remove("/var/reports/" + report_id)
