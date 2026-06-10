from typing import Dict, List

from .report import Finding, Recommendation, Report


GRADE_ORDER = ["A+", "A", "B", "C", "D"]
SCORE_GRADES = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (0, "D"),
]
PUBLIC_D_FLOOR = 40


def score_report(report: Report) -> Report:
    score = 100
    penalized = set()
    for finding in report.findings:
        key = penalty_key(finding)
        if key in penalized:
            continue
        penalized.add(key)
        score -= penalty_for(finding)
    raw_score = max(0, min(100, score))
    report.score = public_score(raw_score)
    report.grade = apply_grade_caps(grade_from_score(report.score), report.findings)
    report.raw.setdefault("scoring", {})["raw_score"] = raw_score
    report.raw["scoring"]["public_score_floor"] = PUBLIC_D_FLOOR
    report.recommendations = unique_recommendations(sorted_findings(report.findings))
    report.summary = explain_grade(report)
    return report


def penalty_for(finding: Finding) -> int:
    if finding.score_penalty:
        return finding.score_penalty
    return {
        "critical": 100,
        "high": 25,
        "medium": 10,
        "low": 5,
        "info": 0,
    }.get(finding.severity, 0)


def penalty_key(finding: Finding) -> str:
    return "|".join(
        [
            finding.code,
            finding.category,
            finding.severity,
            finding.title,
            finding.grade_cap or "",
        ]
    )


def grade_from_score(score: int) -> str:
    for threshold, grade in SCORE_GRADES:
        if score >= threshold:
            return grade
    return "D"


def public_score(raw_score: int) -> int:
    if raw_score <= PUBLIC_D_FLOOR:
        return PUBLIC_D_FLOOR
    return raw_score


def apply_grade_caps(initial_grade: str, findings: List[Finding]) -> str:
    grade = initial_grade
    for finding in findings:
        if finding.grade_cap:
            grade = worse_grade(grade, finding.grade_cap)
    return grade


def worse_grade(left: str, right: str) -> str:
    left = normalize_grade(left)
    right = normalize_grade(right)
    return right if GRADE_ORDER.index(right) > GRADE_ORDER.index(left) else left


def normalize_grade(grade: str) -> str:
    if grade in GRADE_ORDER:
        return grade
    if grade in {"F", "T"}:
        return "D"
    return "D"


def sorted_findings(findings: List[Finding]) -> List[Finding]:
    order: Dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda item: (order.get(item.severity, 9), item.category, item.code))


def unique_recommendations(findings: List[Finding]) -> List[Recommendation]:
    recommendations: List[Recommendation] = []
    seen = set()
    for finding in findings:
        code = finding.recommendation.code
        if code in seen:
            continue
        seen.add(code)
        recommendations.append(finding.recommendation)
    return recommendations


def explain_grade(report: Report) -> List[str]:
    if not report.findings:
        return ["Критичных замечаний не найдено."]
    grouped_caps: Dict[str, List[str]] = {}
    grouped_penalties: Dict[int, List[str]] = {}
    for finding in sorted_findings(report.findings):
        title = str(finding.title or "").strip()
        if not title:
            continue
        if finding.grade_cap:
            cap = normalize_grade(finding.grade_cap)
            bucket = grouped_caps.setdefault(cap, [])
            if title not in bucket:
                bucket.append(title)
            continue
        if finding.score_penalty or finding.severity != "info":
            penalty = penalty_for(finding)
            bucket = grouped_penalties.setdefault(penalty, [])
            if title not in bucket:
                bucket.append(title)

    explanations: List[str] = []
    for cap in GRADE_ORDER[::-1]:
        titles = grouped_caps.get(cap)
        if not titles:
            continue
        explanations.append(
            f"Оценка ограничена до {cap}: " + "; ".join(titles)
        )
    for penalty in sorted(grouped_penalties.keys(), reverse=True):
        titles = grouped_penalties[penalty]
        if not titles:
            continue
        explanations.append(
            f"Потеря баллов ({penalty}): " + "; ".join(titles)
        )
    return explanations or ["Есть информационные рекомендации без влияния на оценку."]
