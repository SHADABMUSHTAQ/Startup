"""Output formatting functions"""
from typing import Dict, Any

def generate_text_report(analysis_result: Dict[str, Any]) -> str:
    """Generate human-readable text report"""
    report = []
    metadata = analysis_result.get("metadata", {})
    stats = analysis_result.get("statistics", {})
    findings = analysis_result.get("findings", [])
    
    report.append("=" * 60)
    report.append("SIEM SECURITY ANALYSIS REPORT")
    report.append("=" * 60)
    report.append(f"File: {metadata.get('file_name', 'N/A')}")
    report.append(f"Path: {metadata.get('file_path', 'N/A')}")
    report.append(f"Analyzed: {metadata.get('analyzed_at', 'N/A')}")
    report.append(f"Duration: {metadata.get('analysis_duration', 0):.2f}s")
    report.append(f"Total Events: {stats.get('total_events', 0)}")
    report.append(f"Total Findings: {stats.get('total_findings', 0)}")
    report.append("-" * 60)
    
    severity_counts = stats.get('findings_by_severity', {})
    if severity_counts:
        report.append("FINDINGS BY SEVERITY:")
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0: report.append(f"  {severity.upper()}: {count}")
        report.append("-" * 60)
    
    if findings:
        report.append("DETAILED FINDINGS:")
        report.append("-" * 60)
        for i, finding in enumerate(findings, 1):
            report.append(f"\n{i}. [{finding.get('severity', 'medium').upper()}] {finding.get('attack_type')}")
            report.append(f"   Summary: {finding.get('summary')}")
            report.append(f"   Explanation: {finding.get('explanation')}")
            if finding.get('source_ips'):
                report.append(f"   Source IPs: {', '.join(finding.get('source_ips'))}")
            if finding.get('matched_keywords'):
                report.append(f"   Keywords: {', '.join(finding.get('matched_keywords'))}")
            if finding.get('count', 1) > 1:
                report.append(f"   Count: {finding.get('count')}")
    else:
        report.append("\nNo security findings detected.")
    
    report.append("=" * 60)
    report.append("Analysis completed successfully.")
    return "\n".join(report)
