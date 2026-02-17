from __future__ import annotations

import argparse
import sys

from app.application.use_cases.benchmark import BenchmarkCommand, BenchmarkUseCase
from app.application.use_cases.crack_hash import CrackHashCommand, CrackHashUseCase
from app.domain.value_objects.search_params import SearchParams
from app.infrastructure.bruteforce.charset import resolve_charset
from app.infrastructure.hashing.factory import get_verifier_cls


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secondlabsecurity")
    sub = parser.add_subparsers(dest="command", required=True)

    crack = sub.add_parser("crack", help="Bruteforce a hash")
    crack.add_argument("--algo", required=True, choices=["md5", "sha1", "bcrypt", "argon2id"])
    crack.add_argument("--hash", required=True, dest="target_hash")
    crack.add_argument("--charset", required=True, help="charset name (digits/lower/...) or literal chars")
    crack.add_argument("--min-len", type=int, required=True)
    crack.add_argument("--max-len", type=int, required=True)
    crack.add_argument("--workers", type=int, default=1)
    crack.add_argument("--time-limit", type=float, default=None, help="seconds")
    crack.add_argument("--max-attempts", type=int, default=None)

    bench = sub.add_parser("bench", help="Benchmark verification speed (fixed attempts)")
    bench.add_argument("--algo", required=True, choices=["md5", "sha1", "bcrypt", "argon2id"])
    bench.add_argument(
        "--hash",
        dest="target_hash",
        default=None,
        help="Target hash (optional). If omitted, a hash from built-in dataset is used.",
    )
    bench.add_argument("--charset", required=True)
    bench.add_argument("--length", type=int, required=True)
    bench.add_argument("--attempts", type=int, required=True)
    bench.add_argument("--workers", type=int, default=1)

    return parser


def _default_hash_for_algo(algo: str) -> str:
    # Valid formats to keep verifiers happy; should be unlikely to be found.
    if algo == "md5":
        return "0" * 32
    if algo == "sha1":
        return "0" * 40
    if algo == "bcrypt":
        # bcrypt hash for password "not-in-space" (format-valid placeholder)
        return "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi"
    if algo == "argon2id":
        return "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c"
    raise ValueError("Unsupported algo")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    algo = args.algo
    verifier_cls = get_verifier_cls(algo)

    if args.command == "crack":
        charset = resolve_charset(args.charset)
        search = SearchParams(charset=charset, min_len=args.min_len, max_len=args.max_len)
        use_case = CrackHashUseCase(verifier_cls=verifier_cls)
        result = use_case.execute(
            CrackHashCommand(
                target_hash=args.target_hash,
                search=search,
                workers=max(1, args.workers),
                time_limit_seconds=args.time_limit,
                max_attempts=args.max_attempts,
            )
        )
        if result.found:
            print(f"FOUND password={result.password!r} attempts={result.attempts} seconds={result.seconds:.6f}")
        else:
            print(f"NOT FOUND attempts={result.attempts} seconds={result.seconds:.6f}")
        print(f"rate={result.rate_per_second:.2f} attempts/sec")
        return 0

    if args.command == "bench":
        charset = resolve_charset(args.charset)
        search = SearchParams(charset=charset, min_len=args.length, max_len=args.length)
        use_case = BenchmarkUseCase(verifier_cls=verifier_cls)
        target_hash = args.target_hash or _default_hash_for_algo(algo)
        result = use_case.execute(
            BenchmarkCommand(
                target_hash=target_hash,
                search=search,
                length=args.length,
                attempts=args.attempts,
                workers=max(1, args.workers),
            )
        )
        print(f"attempts={result.attempts} seconds={result.seconds:.6f}")
        print(f"rate={result.rate_per_second:.2f} attempts/sec")
        return 0

    raise RuntimeError("Unknown command")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

