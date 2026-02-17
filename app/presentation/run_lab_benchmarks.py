from __future__ import annotations

import csv
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from app.application.use_cases.crack_hash import CrackHashCommand, CrackHashUseCase
from app.domain.value_objects.search_params import SearchParams
from app.infrastructure.bruteforce.charset import CHARSETS
from app.infrastructure.hashing.factory import get_verifier_cls


@dataclass(frozen=True, slots=True)
class LabCase:
    algo: str
    label: str
    target_hash: str
    charset: str
    min_len: int
    max_len: int
    workers: int
    time_limit_seconds: float | None = None


def _cases(workers: int) -> list[LabCase]:
    # NOTE: we don't know the real passwords, so these runs may time out.
    # That's fine; we still record rates and time behavior.
    digits = CHARSETS["digits"]
    lower = CHARSETS["lower"]
    alnum = CHARSETS["alnum"]

    return [
        # MD5
        LabCase("md5", "easy", "e10adc3949ba59abbe56e057f20f883e", digits, 1, 8, workers),
        LabCase("md5", "medium", "1f3870be274f6c49b3e31a0c6728957f", lower, 1, 8, workers),
        LabCase("md5", "hard", "77892341aa9dc66e97f5c248782b5d92", alnum, 1, 8, workers),
        LabCase("md5", "very_hard", "686e697538050e4664636337cc3b834f", alnum, 1, 10, workers),
        # SHA-1
        LabCase("sha1", "easy", "7c4a8d09ca3762af61e59520943dc26494f8941b", digits, 1, 8, workers),
        LabCase("sha1", "medium", "d0be2dc421be4fcd0172e5afceea3970e2f3d940", lower, 1, 8, workers),
        LabCase("sha1", "hard", "666846867fc5e0a46a7afc53eb8060967862f333", alnum, 1, 8, workers),
        LabCase("sha1", "very_hard", "6e157c5da4410b7e9de85f5c93026b9176e69064", alnum, 1, 10, workers),
        # bcrypt (slow by design) - we just measure within time limit
        LabCase(
            "bcrypt",
            "easy",
            "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi",
            digits,
            1,
            6,
            workers,
        ),
        LabCase(
            "bcrypt",
            "medium",
            "$2a$10$26GB/T2/6aTsMkTjCgqm/.JP8SUjr32Bhfn9m9smtDiIwM4QIt2ze",
            lower,
            1,
            6,
            workers,
        ),
        LabCase(
            "bcrypt",
            "hard",
            "$2a$10$Q9M0vLLrE4/nu/9JEMXFTewB3Yr9uMdIEZ1Sgdk1NQTjHwLN0asfi",
            alnum,
            1,
            6,
            workers,
        ),
        LabCase(
            "bcrypt",
            "very_hard",
            "$2a$10$yZBadi8Szw0nItV2g96P6eqctI2kbG/.mb0uD/ID9tlof0zpJLLL2",
            alnum,
            1,
            7,
            workers,
        ),
        # Argon2id (slow by design)
        LabCase(
            "argon2id",
            "easy",
            "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c",
            digits,
            1,
            6,
            workers,
        ),
        LabCase(
            "argon2id",
            "medium",
            "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$HYQwRUw9VcfkvqkUQ5ppyYPom6f/ro3ZCXYznhrYZw4",
            lower,
            1,
            6,
            workers,
        ),
        LabCase(
            "argon2id",
            "hard",
            "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$9asGA7Xv3vQBz7Yyh4/Ntw0GQgOg8R6OWolOfRETrEg",
            alnum,
            1,
            6,
            workers,
        ),
        LabCase(
            "argon2id",
            "very_hard",
            "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$+smq45/czydGj0lYNdZVXF++FOXJwrkXt6VUIcEauvo",
            alnum,
            1,
            7,
            workers,
        ),
    ]


def main() -> None:
    workers = int(os.getenv("LAB_WORKERS", "4"))
    out_dir = Path("out")
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []

    for case in _cases(workers):
        verifier_cls = get_verifier_cls(case.algo)
        use_case = CrackHashUseCase(verifier_cls=verifier_cls)
        search = SearchParams(charset=case.charset, min_len=case.min_len, max_len=case.max_len)

        t0 = time.perf_counter()
        res = use_case.execute(
            CrackHashCommand(
                target_hash=case.target_hash,
                search=search,
                workers=case.workers,
                time_limit_seconds=case.time_limit_seconds,
                max_attempts=None,
            )
        )
        t1 = time.perf_counter()

        row = {
            "algo": case.algo,
            "label": case.label,
            "hash": case.target_hash,
            "charset_size": len(case.charset),
            "min_len": case.min_len,
            "max_len": case.max_len,
            "workers": case.workers,
            "time_limit_seconds": case.time_limit_seconds,
            "found": res.found,
            "password": res.password,
            "attempts": res.attempts,
            "seconds": res.seconds,
            "wall_seconds": t1 - t0,
            "rate_per_second": res.rate_per_second,
        }
        results.append(row)
        print(
            f"{case.algo}/{case.label}: found={res.found} attempts={res.attempts} "
            f"seconds={res.seconds:.6f} rate={res.rate_per_second:.2f}/s"
        )

    csv_path = out_dir / "results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=sorted(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    json_path = out_dir / "results.json"
    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Saved: {csv_path} and {json_path}")


if __name__ == "__main__":
    main()

