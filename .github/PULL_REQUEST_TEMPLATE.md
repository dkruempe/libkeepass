<!-- Thank you for contributing to libkeepass! Please fill out this template
     so that maintainers and reviewers can understand your change quickly.
     See CONTRIBUTING.md for the code style and check requirements. -->

## Description

<!-- A short summary of what this pull request changes and why. -->

## Related issue

<!-- Link the issue(s) this PR fixes or relates to, if any, e.g. "Fixes #123"
     or "Closes #456". If there is no issue, please describe the motivation
     in the Description field. -->

## Type of change

<!-- Tick the box that applies. Mark only what this PR actually changes. -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes the public API)
- [ ] Documentation / CI / build system change
- [ ] Test addition or improvement

## Checklist

<!-- Verify the items that apply before requesting a review. -->

- [ ] The whole test suite passes: `ctest --test-dir build --output-on-failure`
- [ ] Formatting is clean: `clang-format --dry-run --Werror $(git ls-files '*.cc' '*.hh')`
- [ ] New public API is documented with Doxygen comments in `src/include/libkeepass/`
- [ ] User-facing changes are reflected in `CHANGELOG.md` (Keep a Changelog format)
- [ ] Reference to the conan center issue / packaging impact, if any

## Test plan

<!-- Describe how you tested the change: which databases/ciphers/KDFs you
     exercised, which test binaries you ran, whether you ran the fuzz targets,
     etc. -->

## Additional context

<!-- Anything else reviewers should know. -->