# Contributing to Horcrux

Welcome to the Horcrux project! We're thrilled that you're interested in contributing. Horcrux a multi-party-computation signing service for CometBFT nodes. This document outlines the process and guidelines for contributing to Horcrux. Please read it carefully to ensure that you understand our workflow and the standards we expect for our community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Contributing Guidelines](#contributing-guidelines)
- [Issues](#issues)
- [Pull Requests](#pull-requests)
- [Responsibilities of a PR Reviewer](#responsibilities-of-a-pr-reviewer)

## Code of Conduct

Please review our [Code of Conduct](./CODE_OF_CONDUCT.md) to understand the standards and expectations for participating in our community. We are committed to fostering a welcoming and inclusive environment.

## Getting Started

Before you start contributing, make sure you have the following prerequisites installed:

- [Go](https://golang.org/dl/)
- [Docker](https://www.docker.com/get-started)
- [VSCode (recommended editor)](https://code.visualstudio.com/)
- [Make](https://www.gnu.org/software/make/)

To get started, follow these steps:

1. Fork the Horcrux repository to your own GitHub account.

2. Clone your forked repository to your local machine:

   ```sh
   git clone https://github.com/<Username>/horcrux.git
   ```

3. Crate a new branch on your fork

    ```sh
    git checkout -b name/broad-description-of-feature    
    ```

4. Make your changes and commit them with descriptive commit messages.
5. Test your changes locally with `make test`, or by running the specific test affecting your feature or fix.
6. You can validate your changes with `make build` or `make install`.
7. Push your changes to your github forked repository

    ```sh
    git push origin name/broad-description-of-feature
    ```

8. Create a pull request (PR) against the main branch of the Horcrux repository. If the PR is still a work-in-progress, please mark the PR as draft.

## Contributing Guidelines

- Adhere to the project's coding style and conventions.
- Write clear and concise commit messages and PR descriptions.
- Be responsive to feedback and collaborate with others.
- Document code and include appropriate tests.
- For documentation or typo fixes, submit separate PRs.
- Keep PRs focused on a single issue or feature.

## Issues

We welcome bug reports, feature requests, and other contributions to our project. To open an issue, please follow these guidelines:

1) Search existing issues: Before opening a new issue, please search existing issues to ensure that is not a duplicates.
2) Provide a clear and descriptive title: This helps others understand the nature of the issue at a glance.
3) Provide detailed information: In the issue description, clearly state the purpose of the issue and follow the guidelines of the issue template
4) A maintainer will take care of assigning the appropriate labels to your issue, if applicable.

## Pull requests

In almost all cases, you should target branch `main` with your work.
For internal branches, branch names should be prefixed with the author's name followed by a short description of the feature, eg. `name/feature-x`.
Pull requests are made against `main` and are squash-merged into main after approval. All CI pipeline test must pass for this to be the case.

## Responsibilities of a PR Reviewer

As a PR reviewer, your primary responsibility is to guide the PR through to completion. This entails not only identifying and addressing issues within the PR but also taking a leadership role in resolving any decisions necessary for the PR to be merged successfully.

In cases where you are assigned as a reviewer for a PR that pertains to an unfamiliar part of the codebase, it's perfectly acceptable to delegate the review to a more knowledgeable colleague, provided they are willing to assume that responsibility. This ensures that the PR receives expert attention and increases the likelihood of its successful merging. Collaboration and teamwork are key in maintaining code quality and project progress.

---

We appreciate your contributions and look forward to working with you to make Horcrux a continued valuable resource. If you have any questions or need assistance, feel free to reach out to the maintainers, community members, or <hello@strange.love>.
