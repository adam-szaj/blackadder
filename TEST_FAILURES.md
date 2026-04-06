# Test Failures Summary

Tests are failing due to multiple issues introduced after refactoring:

## 1. Address Overflow (FIXED)
- Problem: Kernel-space addresses (0xffff...) exceeded signed 64-bit integer range
- Solution: Added `to_signed_64bit()` function to convert unsigned to signed 64-bit values

## 2. Program Header Parsing (FIXED)
- Problem: Regex didn't capture space-separated flags in readelf output
- Solution: Updated regex to `([\w\-\s]+?)` to capture flags with spaces

## 3. Configuration Fixture (FIXED)
- Problem: Tests referenced `config` fixture that didn't exist (only `test_config`)
- Solution: Added `config` alias fixture pointing to `test_config`

## 4. Detached Instance/Lazy Loading (CURRENT)
- Problem: After session closes, tests can't access `process.mappings` because it's a lazy-loaded relationship
- Cause: SQLAlchemy async doesn't allow lazy-loading after detachment, even with `expire_on_commit=False`
- Tests expect to access `process.mappings` after `load_maps()` returns

## Options to Fix:

### A. Eagerly Load in Session
Use `selectinload()` or explicitly fetch with joined loads before returning

### B. Return DTO Instead
Convert ProcessSnapshot to dictionary/dataclass with eager-loaded data

### C. Refactor Tests
Make tests work within the async context or use different assertions

### D. Use Object.__setattr__
Replace lazy relationship with actual list before returning (complex/fragile)

## Next Steps
Need to decide on approach and implement fix that works for all process_db tests that access relationships.
