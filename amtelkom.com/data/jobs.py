from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class JobSection:
    heading: str
    paragraphs: tuple[str, ...] = ()
    bullets: tuple[str, ...] = ()


@dataclass(frozen=True)
class Job:
    slug: str
    title: str
    summary: str
    location: str
    positions: str
    opening_date: str
    deadline: str
    icon: str = "fa-briefcase"
    is_open: bool = True
    sections: tuple[JobSection, ...] = field(default_factory=tuple)

    @property
    def legacy_url(self) -> str:
        return f"/jobs/{self.slug}"

    @property
    def mail_subject(self) -> str:
        return f"Application for {self.title} Position"


JOBS: tuple[Job, ...] = (
    Job(
        slug="oss-bss-engineer",
        title="OSS/BSS Engineer",
        summary=(
            "Manage, support, and optimize convergent billing, CRM, mediation, "
            "rating, and provisioning systems for telecom operations."
        ),
        location="Mogadishu, Somalia",
        positions="1 Position",
        opening_date="May 11, 2026",
        deadline="May 20, 2026",
        icon="fa-network-wired",
        sections=(
            JobSection(
                "About AMTEL",
                paragraphs=(
                    "AMTEL Ltd is one of the leading telecommunications companies in Somalia, providing data, mobile and fixed voice, 4G, 3G, 2G messaging, mobile money services, cloud services, broadband internet, and ISP services.",
                ),
            ),
            JobSection(
                "Job Summary",
                paragraphs=(
                    "We are looking for a skilled Convergent Billing System Engineer (CBS & CRM) to manage, support, and optimize convergent billing platforms for telecom and digital service operations.",
                ),
            ),
            JobSection(
                "Key Responsibilities",
                bullets=(
                    "Support billing, charging, CRM, mediation, and customer management systems.",
                    "Ensure accurate billing and revenue assurance processes.",
                    "Configure and maintain prepaid/postpaid operations including tariff and bundle configurations.",
                    "Support order management and customer provisioning workflows.",
                    "Troubleshoot OSS/BSS incidents and perform root-cause analysis.",
                    "Monitor system performance and implement improvements.",
                    "Participate in system upgrades, migrations, and deployments.",
                    "Prepare technical documentation and operational procedures.",
                    "Work with vendors and internal stakeholders during implementation projects.",
                ),
            ),
            JobSection(
                "Required Qualifications",
                bullets=(
                    "Bachelor's degree in Telecommunications, Computer Science, Information Technology, Engineering, or a related field.",
                    "Minimum of 3 years' experience in OSS/BSS operations or telecom systems.",
                    "Strong understanding of telecom network architecture.",
                    "Knowledge of billing systems, CRM platforms, mediation systems, provisioning tools, and service assurance tools.",
                    "Familiarity with Linux/Unix environments.",
                    "Understanding of databases such as Oracle, MySQL, or PostgreSQL.",
                    "Experience with cloud and virtualization technologies.",
                ),
            ),
        ),
    ),
    Job(
        slug="senior-developer",
        title="Senior Developer",
        summary="Lead the design, development, and maintenance of secure, scalable fintech systems.",
        location="Mogadishu and Garowe, Somalia",
        positions="2 Positions",
        opening_date="January 12, 2026",
        deadline="January 19, 2026",
        icon="fa-code",
        is_open=False,
        sections=(
            JobSection(
                "Background",
                paragraphs=(
                    "AMTEL is seeking an experienced Senior Developer to build secure, scalable, high-availability fintech systems and support business growth.",
                ),
            ),
            JobSection(
                "Skills",
                bullets=(
                    "Strong proficiency in Java 17+ and Spring Boot.",
                    "Experience with JPA, Hibernate, Spring Data JPA, REST APIs, RabbitMQ, Redis, and SQL Server Enterprise.",
                    "Understanding of microservices and distributed system architecture.",
                    "Ability to troubleshoot complex system issues and optimize application performance.",
                ),
            ),
        ),
    ),
    Job(
        slug="senior-database-engineer",
        title="Senior Database Engineer",
        summary="Lead database administration, optimization, data engineering, security, and reporting.",
        location="Mogadishu, Somalia",
        positions="1 Position",
        opening_date="January 12, 2026",
        deadline="January 19, 2026",
        icon="fa-database",
        is_open=False,
        sections=(
            JobSection(
                "Background",
                paragraphs=(
                    "AMTEL is seeking a Senior Database Engineer to support mission-critical fintech databases, high availability, performance optimization, and data reliability.",
                ),
            ),
            JobSection(
                "Skills",
                bullets=(
                    "Expert knowledge of SQL Server Enterprise 2022 architecture and internals.",
                    "Strong experience with Always On Availability Groups, backup, restore, and maintenance strategies.",
                    "Advanced skills in database security, ETL, T-SQL, and performance tuning.",
                    "Experience with Power BI, SSRS, or similar BI tools.",
                ),
            ),
        ),
    ),
)


def get_open_jobs() -> tuple[Job, ...]:
    return tuple(job for job in JOBS if job.is_open)


def get_job(slug: str) -> Job | None:
    return next((job for job in JOBS if job.slug == slug), None)
