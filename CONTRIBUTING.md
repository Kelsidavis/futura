# Contributing to Futura OS

Thank you for your interest in contributing to Futura OS! This document provides guidelines and best practices for contributors.

---

## 🎯 How to Contribute

### Reporting Issues

Before creating an issue:
1. **Search existing issues** to avoid duplicates
2. **Provide clear reproduction steps** for bugs
3. **Include system information** (OS, architecture, build configuration)
4. **Attach relevant logs** or error messages

### Suggesting Features

Feature requests should include:
- **Clear use case**: Why is this feature needed?
- **Proposed design**: How should it work?
- **Alternatives considered**: What other approaches did you explore?
- **Compatibility impact**: Does this break existing APIs?

---

## 🏗️ Development Workflow

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
git clone https://github.com/YOUR_USERNAME/futura.git
cd futura
git remote add upstream https://github.com/kelsidavis/futura.git
```

### 2. Create a Branch

```bash
# Create a descriptive branch name
git checkout -b feature/add-network-stack
# or
git checkout -b fix/scheduler-deadlock
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `refactor/` - Code refactoring
- `docs/` - Documentation updates
- `test/` - Test additions or fixes

### 3. Make Changes

Follow the [Coding Standards](#coding-standards) below.

### 4. Test Your Changes

```bash
# Build the kernel
make clean && make

# Run in QEMU (when test harness is available)
make test

# Run static analysis (future)
make lint
```

### 5. Commit Your Changes

Write clear, descriptive commit messages:

```
Add async network socket implementation

- Implement fut_socket_create() and fut_socket_bind()
- Add non-blocking send/receive operations
- Integrate with object system for capability checks
- Add unit tests for socket lifecycle

Closes #123
```

Commit message guidelines:
- **First line**: Imperative mood, max 72 characters
- **Body**: Explain what and why, not how
- **Footer**: Reference related issues

### 6. Push and Create Pull Request

```bash
git push origin feature/add-network-stack
```

Then create a Pull Request on GitHub with:
- **Clear title** summarizing the change
- **Description** explaining the motivation
- **Testing notes** describing how you tested
- **Breaking changes** if any APIs were modified

---

## 📝 Coding Standards

### General Principles

1. **Clean and readable** - Code is read more often than written
2. **Self-documenting** - Use descriptive names, add comments for complex logic
3. **Minimal** - Only add code that solves real problems
4. **Tested** - Ensure changes don't break existing functionality

### C Code Style

#### Naming Conventions

```c
// Functions: snake_case with prefix
void fut_thread_create(...);
void fut_mem_alloc(...);

// Types: snake_case with _t suffix
typedef struct fut_thread fut_thread_t;
typedef enum fut_object_type fut_object_type_t;

// Constants/Macros: SCREAMING_SNAKE_CASE with prefix
#define FUT_PAGE_SIZE 4096
#define FUT_MAX_THREADS 256

// Enum values: PREFIX_ENUM_VALUE
enum fut_thread_state {
    FUT_THREAD_READY,
    FUT_THREAD_RUNNING,
    FUT_THREAD_SLEEPING
};
```

#### Formatting

- **Indentation**: 4 spaces (no tabs)
- **Line length**: Max 100 characters
- **Braces**: K&R style (opening brace on same line)

```c
// Good
if (condition) {
    do_something();
    do_another_thing();
}

// Bad
if (condition)
{
    do_something();
}
```

#### Comments

```c
/* ============================================================
 *   Section Header
 * ============================================================ */

/**
 * Brief function description.
 *
 * Detailed explanation of what the function does, any side effects,
 * and important usage notes.
 *
 * @param param1 Description of parameter 1
 * @param param2 Description of parameter 2
 * @return Description of return value
 */
int fut_example_function(int param1, void *param2) {
    // Single-line comment for implementation detail
    return 0;
}
```

#### File Headers

```c
/* filename.c - Futura OS Component Name
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Brief description of what this file implements.
 */

#include "../../include/kernel/fut_component.h"
```

### Assembly Code Style

```asm
/* filename.S - Futura OS Platform-Specific Code
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

.section .text
.global fut_function_name

/* ============================================================
 *   Function Name
 * ============================================================
 *
 * Description of what this function does.
 * Register conventions and calling convention notes.
 */

fut_function_name:
    /* Save registers */
    push %ebx
    push %esi

    /* Function body */
    movl 8(%esp), %eax

    /* Restore and return */
    pop %esi
    pop %ebx
    ret

.size fut_function_name, . - fut_function_name
```

---

## 🧪 Testing Guidelines

### Unit Tests (Phase 2)

```c
// Test naming: test_component_scenario()
void test_thread_creation_success(void) {
    fut_task_t *task = fut_task_create();
    fut_thread_t *thread = fut_thread_create(task, entry_point, NULL, 4096, 128);

    assert(thread != NULL);
    assert(thread->state == FUT_THREAD_READY);

    fut_object_destroy(thread);
    fut_object_destroy(task);
}
```

### Integration Tests (Phase 2)

Test complete workflows end-to-end:
- File creation, write, read, close
- Thread creation, scheduling, termination
- IPC message send and receive

---

## 📚 Documentation

### Code Documentation

- **All public APIs** must have Doxygen-style comments
- **Complex algorithms** should have explanatory comments
- **Platform-specific code** should document hardware interactions

### Markdown Documentation

- Update relevant docs in `docs/` when adding features
- Include code examples for new APIs
- Keep documentation in sync with code

---

## 🔍 Code Review Process

All contributions go through code review:

1. **Automated checks**: Build, tests, linting (when available)
2. **Maintainer review**: Architecture, code quality, style
3. **Feedback**: Address review comments
4. **Approval**: At least one maintainer approval required
5. **Merge**: Squash and merge to main branch

### Review Criteria

Reviewers will check for:
- ✅ Code follows style guidelines
- ✅ Changes are well-tested
- ✅ Documentation is updated
- ✅ No breaking changes (or properly documented)
- ✅ Commit messages are clear
- ✅ Code is maintainable and readable

---

## 🚀 Release Process

Futura OS follows semantic versioning:

- **Major (1.0.0)**: Breaking changes
- **Minor (0.1.0)**: New features, backward compatible
- **Patch (0.0.1)**: Bug fixes

Releases are tagged and include:
- Changelog with all changes since last release
- Migration guide for breaking changes
- Binary artifacts for supported platforms

---

## 📞 Getting Help

- **Questions**: Use GitHub Discussions
- **Real-time chat**: (To be announced)
- **Email**: dumbandroid@gmail.com

---

## 🏆 Recognition

Contributors will be:
- Listed in `CONTRIBUTORS.md` (Phase 2)
- Credited in release notes
- Acknowledged in documentation for major contributions

---

## 📜 License

By contributing to Futura OS, you agree that your contributions will be licensed under the **Mozilla Public License 2.0** (MPL-2.0).

You certify that:
1. The contribution is your original work
2. You have the right to submit it under MPL-2.0
3. You understand and agree to the license terms

---

Thank you for contributing to Futura OS! 🚀
