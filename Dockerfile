# onedroid-witness: standard-library Python plus ssh-keygen (SSH signatures, as sign.py and check.py use).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 witness
WORKDIR /app
COPY onedroid_witness /app/onedroid_witness
COPY vendor /app/vendor
# the build context may carry owner-only modes (a workspace with umask 077); the service runs as an unprivileged user and must read its code
RUN chmod -R a+rX /app
USER witness
# the configuration, the key directory (a volume) and the OpenRouter key file (a Secret mount) are given at run time:
#   /etc/onedroid-witness/config.json   {"models": [...], "daily_cap_usd": 2, "keys_dir": "/var/lib/onedroid-witness/keys",
#                                        "jobs_dir": "/var/lib/onedroid-witness/jobs", "ledger_path": "/var/lib/onedroid-witness/ledger.json",
#                                        "check_py": "/app/vendor/check.py", "openrouter_key_file": "/etc/onedroid-witness/openrouter/key",
#                                        "private_mode": false, "port": 8080}
EXPOSE 8080
ENTRYPOINT ["python3", "-m", "onedroid_witness.cli"]
CMD ["serve", "--config", "/etc/onedroid-witness/config.json"]
