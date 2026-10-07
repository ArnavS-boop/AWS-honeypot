#!/usr/bin/env python3

import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = 9000

INFRA_ROOT = "/opt/.infra"

FILESYSTEM_SCRIPT = f"{INFRA_ROOT}/setup-filesystem.sh"
COWRIE_SCRIPT = f"{INFRA_ROOT}/setup-cowrie.sh"

ALLOWED_PROFILES = {
    "baseline",
    "investigation",
}


def run_command(command):
    print(f"[controller] running: {' '.join(command)}", flush=True)

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    print(result.stdout, flush=True)

    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}"
        )


def apply_profile(profile):
    if profile not in ALLOWED_PROFILES:
        raise ValueError(f"Unknown profile: {profile}")

    print(f"[controller] Applying profile: {profile}", flush=True)

    # First clean the filesystem state left by the previous profile.
    run_command([
        "/bin/bash",
        FILESYSTEM_SCRIPT,
        f"clean/{profile}",
    ])

    # Then create the requested real filesystem state.
    run_command([
        "/bin/bash",
        FILESYSTEM_SCRIPT,
        profile,
    ])

    # Finally switch Cowrie's active filesystem and restart Cowrie.
    run_command([
        "/bin/bash",
        COWRIE_SCRIPT,
        profile,
    ])

    print(f"[controller] Profile '{profile}' applied", flush=True)


class ControllerHandler(BaseHTTPRequestHandler):

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def do_GET(self):

        if self.path == "/health":
            self.send_json(
                200,
                {
                    "status": "ok",
                    "service": "decoy-controller",
                },
            )
            return

        self.send_json(
            404,
            {
                "error": "not found",
            },
        )

    def do_POST(self):

        if self.path != "/profile":
            self.send_json(
                404,
                {
                    "error": "not found",
                },
            )
            return

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )

            if content_length <= 0:
                raise ValueError("empty request body")

            body = self.rfile.read(content_length)

            request = json.loads(body.decode("utf-8-sig"))

            profile = request.get("profile")

            if profile not in ALLOWED_PROFILES:
                self.send_json(
                    400,
                    {
                        "error": "invalid profile",
                        "allowed": sorted(ALLOWED_PROFILES),
                    },
                )
                return

            apply_profile(profile)

            self.send_json(
                200,
                {
                    "status": "applied",
                    "profile": profile,
                },
            )

        except json.JSONDecodeError:
            self.send_json(
                400,
                {
                    "error": "invalid JSON",
                },
            )

        except ValueError as exc:
            self.send_json(
                400,
                {
                    "error": str(exc),
                },
            )

        except Exception as exc:
            print(
                f"[controller] ERROR: {exc}",
                flush=True,
            )

            self.send_json(
                500,
                {
                    "status": "failed",
                    "error": str(exc),
                },
            )

    def log_message(self, format_string, *args):
        print(
            "[controller]",
            format_string % args,
            flush=True,
        )


def main():

    print(
        f"[controller] Listening on {HOST}:{PORT}",
        flush=True,
    )

    server = ThreadingHTTPServer(
        (HOST, PORT),
        ControllerHandler,
    )

    server.serve_forever()


if __name__ == "__main__":
    main()