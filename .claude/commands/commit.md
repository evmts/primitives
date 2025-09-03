---
allowed-tools: Bash(git status:*), Bash(git diff:*), Bash(git add:*), Bash(git commit:*)
argument-hint: [--dry-run] [--all]
description: Analyze git changes and create atomic conventional commits with emoji prefixes
model: claude-sonnet-4-20250514
---

# Intelligent Git Commit Command

Analyze the current git repository state and create atomic, conventional commits with emoji prefixes. Automatically filter out temporary/debug files and group related changes logically.

## Instructions

1. **Analyze Repository State**

   - Run `git status --porcelain` to see all changes
   - Run `git diff --cached` to see staged changes
   - Run `git diff` to see unstaged changes
   - Show a summary of what files have changed

2. **Filter Temporary Files**
   Unless `--all` is specified in $ARGUMENTS, automatically exclude these patterns:

   - Files starting with `test_`, `debug_`, `temp_`
   - Files ending with `.tmp`, `.log`, `.bak`, `.swp`, `.swo`, `~`
   - IDE directories: `.vscode/`, `.idea/`, `.vs/`
   - Build artifacts: `node_modules/`, `target/debug/`, `target/release/`, `.zig-cache/`, `zig-out/`
   - OS files: `.DS_Store`, `Thumbs.db`

   Explain what files were filtered out and why.

3. **Group Changes Logically**
   Group files into logical atomic commits based on:

   - **EVM module**: `src/evm/` files
   - **Core functionality**: `src/` files (non-EVM)
   - **Tests**: `test/` files or files containing "test"
   - **Documentation**: `.md` files or `doc/` files
   - **Build system**: `build.zig`, build-related files
   - **Benchmarks**: `bench/` files
   - **Claude Code**: `.claude/`, `CLAUDE.md` files
   - **Miscellaneous**: Everything else

4. **Determine Commit Types**
   For each group, analyze and determine the appropriate conventional commit type:

   - **🎉 feat**: New features or functionality
   - **🐛 fix**: Bug fixes
   - **♻️ refactor**: Code refactoring without functional changes
   - **📚 docs**: Documentation updates
   - **✅ test**: Adding or updating tests
   - **🔧 chore**: Maintenance tasks, dependency updates
   - **🎨 style**: Code style/formatting changes
   - **⚡ perf**: Performance improvements
   - **🔨 build**: Build system changes
   - **👷 ci**: CI/CD changes

5. **Create Atomic Commits**
   For each logical group:

   - Stage the files with `git add <files>`
   - Create a commit with this exact format:

   ```
   {emoji} {type}: {description}

   🤖 Generated with [Claude Code](https://claude.ai/code)

   Co-Authored-By: Claude <noreply@anthropic.com>
   ```

6. **Dry Run Mode**
   If `--dry-run` is in $ARGUMENTS:
   - Show what commits would be made without executing them
   - List the files that would be included in each commit
   - Explain the reasoning for each commit type and grouping

## Examples of Good Commit Messages

- `🎉 feat: Add storage state tracking to EVM tracer`
- `🐛 fix: Resolve memory leak in stack operations`
- `♻️ refactor: Simplify bytecode dispatch logic`
- `📚 docs: Update API documentation for tracers`
- `✅ test: Add comprehensive tracer test suite`
- `🔧 chore: Update dependencies and build configuration`

## Important Guidelines

- **Be atomic**: Each commit should contain related changes only
- **Be descriptive**: Commit messages should clearly explain what changed and why
- **Follow conventions**: Use conventional commit format with appropriate emoji
- **Avoid temporary files**: Don't commit debug, test, or temporary files unless explicitly requested
- **Group logically**: Related changes should be in the same commit
- **Ask before committing**: Show the plan and ask for confirmation before executing commits

## Safety Checks

Before creating any commits:

1. Verify no sensitive information (API keys, passwords, tokens) is being committed
2. Ensure build artifacts and temporary files are properly filtered
3. Check that test files are not mixed with production code changes
4. Confirm that each commit represents a logical, atomic change

Arguments: $ARGUMENTS
