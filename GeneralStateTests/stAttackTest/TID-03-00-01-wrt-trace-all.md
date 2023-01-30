> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stAttackTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stAttackTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-cases are failed,

- Execution time taking too long, Consuming too much of CPU & system memory. Have to review the OpCode

| Test ID | Use-Case |
| --- | --- |
|  TID-03-01 |  ContractCreationSpam |

* Following use-case are skipped due to `transaction.tx` empty. Have to re-check on revm.

| Test ID | Use-Case |
| --- | --- |
| TID-03-02 | CrashingTransaction |


> Execution Trace

```
 Finished release [optimized] target(s) in 0.19s
     Running `target/release/evm_eth_compliance statetest`
2023-01-27T07:38:45.266847Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json", Total Files :: 1
2023-01-27T07:38:45.296304Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:38:45.296448Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:38:45.296454Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:38:45.296511Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:38:45.296587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:38:45.296592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ContractCreationSpam"::Istanbul::0
2023-01-27T07:38:45.296596Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
2023-01-27T07:38:45.296600Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:38:45.296605Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 140, 122, 132, 212, 242, 135, 36, 65, 73, 159, 167, 43, 72, 189, 69, 176, 57, 35, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
^C

2023-01-27T07:26:00.561661Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json", Total Files :: 1
2023-01-27T07:26:00.592447Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:26:00.592605Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:26:00.592687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:26:00.592691Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::Istanbul::0
2023-01-27T07:26:00.592694Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-27T07:26:00.592697Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-27T07:26:00.592698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:26:00.592699Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::Berlin::0
2023-01-27T07:26:00.592701Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-27T07:26:00.592703Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-27T07:26:00.592705Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:26:00.592707Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::London::0
2023-01-27T07:26:00.592709Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-27T07:26:00.592711Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-27T07:26:00.592712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:26:00.592714Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::Merge::0
2023-01-27T07:26:00.592716Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-27T07:26:00.592718Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-27T07:26:00.593650Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:278.148s
```