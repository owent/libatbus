---
name: engineering-guidelines
description: "Use when: writing or reviewing C++, public headers, template function visibility, exported API ABI, ATFW_UTIL_SYMBOL_VISIBLE, or ATFW_UTIL_FORCEINLINE."
---

# Engineering Guidelines

Use this skill before writing or reviewing C++ in `libatbus`.

## Header and ABI boundaries

- Classify each interface as public library API or non-exported internal code before choosing a visibility marker.
- Every public non-template API must use `ATBUS_MACRO_API` (or its matching `*_API` macro) on the declaration or
  enclosing type, or use `ATFW_UTIL_FORCEINLINE` for a header definition. Plain/implicit `inline` and `constexpr` alone
  do not satisfy this public-API rule.
- A public template function defined in a header may instead use `ATFW_UTIL_SYMBOL_VISIBLE`: a non-inlined instantiation
  can share one visible copy across linked targets, while an inlined call embeds a per-target copy. Keep the definition
  ODR-identical for every consumer so all copies have identical behavior.
- Keep non-template implementations covered by an export macro in `.cpp` files by default.
- Non-exported internal helpers may use ODR-correct implicit inline, `constexpr`, or intentional plain `inline`.

## Review and validation

- For touched public headers, verify the publication model, template visibility, and ODR-identical definition together.
- Preserve generated protocol code unless its source of truth is in scope.
- Run `clang-format` for changed C++ files and `git diff --check` for the scoped changes.
