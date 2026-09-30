# Contributing

Issues and focused pull requests are welcome. Please:

- explain the user-facing problem and keep changes narrowly scoped;
- add or update parser and rule tests for behavior changes;
- keep network tests mocked and never include live-target scans or secrets;
- document new checks, exit codes, and output fields in the README.

Run the local checks before submitting:

```console
python -m pytest
```
