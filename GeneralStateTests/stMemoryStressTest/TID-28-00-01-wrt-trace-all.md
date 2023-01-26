> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stMemoryStressTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stMemoryStressTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case failed

- Hit with error `SYS_ILLEGAL_INSTRUCTION` (ExitCode::4)

| Test ID | Use-Case |
| --- | --- |
| TID-28-01 | CALL_Bounds |
| TID-28-02 | CALL_Bounds2 |
| TID-28-09 | CREATE_Bounds |
| TID-28-12 | DELEGATECALL_Bounds |
| TID-28-35 | static_CALL_Bounds |
| TID-28-36 | static_CALL_Bounds2 |

- Hit with error `USR_ASSERTION_FAILED` (ExitCode::24)

| Test ID | Use-Case |
| --- | --- |
| TID-28-10 | CREATE_Bounds2 |
| TID-28-23 | mload32bitBound_return |
| TID-28-24 | mload32bitBound_return2 |

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-28-05 | CALLCODE_Bounds |
| TID-28-06 | CALLCODE_Bounds2 |
| TID-28-07 | CALLCODE_Bounds3 |
| TID-28-08 | CALLCODE_Bounds4 |

- Hit with error `EVM_CONTRACT_STACK_OVERFLOW` (ExitCode::37)

| Test ID | Use-Case |
| --- | --- |
| TID-28-16 | FillStack |

- Hit with error `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS` (ExitCode::38)

| Test ID | Use-Case |
| --- | --- |
| TID-28-03 | CALL_Bounds2a |
| TID-28-04 | CALL_Bounds3 |
| TID-28-11 | CREATE_Bounds3 |
| TID-28-13 | DELEGATECALL_Bounds2 |
| TID-28-14 | DELEGATECALL_Bounds3 |
| TID-28-25 | MLOAD_Bounds |
| TID-28-26 | MLOAD_Bounds2 |
| TID-28-28 | MSTORE_Bounds |
| TID-28-29 | MSTORE_Bounds2 |
| TID-28-20 | mload32bitBound |
| TID-28-21 | mload32bitBound2 |
| TID-28-22 | mload32bitBound_Msize |
| TID-28-37 | static_CALL_Bounds2a |
| TID-28-38 | static_CALL_Bounds3 |

- Hit with error `EVM_CONTRACT_BAD_JUMPDEST` (ExitCode::39)

| Test ID | Use-Case |
| --- | --- |
| TID-28-19 | JUMPI_Bounds |
| TID-28-17 | JUMP_Bounds |
| TID-28-18 | JUMP_Bounds2 |
