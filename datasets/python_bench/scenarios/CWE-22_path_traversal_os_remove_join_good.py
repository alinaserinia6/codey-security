"""os_remove_join (CWE-22) - good variant.

Generated benchmark file. The good variant is the repaired form of this scenario.
"""
import os


def purge_report(report_id):
    safe = os.path.basename(report_id)
    os.remove(os.path.join("/var/reports", safe))
