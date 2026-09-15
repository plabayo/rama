CI retains all existing checks while sharing five macOS and four Windows runner
slots across workflows. Heavy jobs wait for the Linux prechecks, and `CI success`
gates deployment. Validate changes with [check_workflows.py](check_workflows.py),
[test_workflows.py](test_workflows.py), and
[check_feature_coverage.py](check_feature_coverage.py).
