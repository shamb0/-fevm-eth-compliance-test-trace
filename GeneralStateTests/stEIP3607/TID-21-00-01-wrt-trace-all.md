> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stEIP3607

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stEIP3607 \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case failed

* Following use-case are skipped due to `transaction.tx` empty. Have to re-check on revm

| Test ID | Use-Case |
| --- | --- |
| TID-21-01 | initCollidingWithNonEmptyAccount |
| TID-21-04 | transactionCollidingWithNonEmptyAccount_init |

> Execution Trace

```
2023-01-26T10:51:49.575759Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json", Total Files :: 1
2023-01-26T10:51:49.624393Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:51:49.624578Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:49.624582Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:51:49.624640Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:49.624642Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:51:49.624704Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:49.624706Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:51:49.624759Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:49.624831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:51:49.624835Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::London::0
2023-01-26T10:51:49.624838Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624841Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:49.624843Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:51:49.624845Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::London::1
2023-01-26T10:51:49.624846Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624849Z  WARN evm_eth_compliance::statetest::runner: TX len : 40
2023-01-26T10:51:49.624850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:51:49.624852Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::London::2
2023-01-26T10:51:49.624854Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624856Z  WARN evm_eth_compliance::statetest::runner: TX len : 16
2023-01-26T10:51:49.624857Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:51:49.624859Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::London::3
2023-01-26T10:51:49.624861Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624863Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T10:51:49.624865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T10:51:49.624866Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::London::4
2023-01-26T10:51:49.624868Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624870Z  WARN evm_eth_compliance::statetest::runner: TX len : 37
2023-01-26T10:51:49.624871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:51:49.624873Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::Merge::0
2023-01-26T10:51:49.624875Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624877Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:49.624879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:51:49.624880Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::Merge::1
2023-01-26T10:51:49.624882Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624884Z  WARN evm_eth_compliance::statetest::runner: TX len : 40
2023-01-26T10:51:49.624886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:51:49.624887Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::Merge::2
2023-01-26T10:51:49.624889Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624892Z  WARN evm_eth_compliance::statetest::runner: TX len : 16
2023-01-26T10:51:49.624893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:51:49.624895Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::Merge::3
2023-01-26T10:51:49.624897Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624899Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T10:51:49.624901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T10:51:49.624903Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "initCollidingWithNonEmptyAccount"::Merge::4
2023-01-26T10:51:49.624905Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/initCollidingWithNonEmptyAccount.json"
2023-01-26T10:51:49.624908Z  WARN evm_eth_compliance::statetest::runner: TX len : 37
2023-01-26T10:51:49.625760Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:521.402s
2023-01-26T10:51:49.893180Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json", Total Files :: 1
2023-01-26T10:51:49.922831Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:51:49.923018Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:49.923022Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:51:49.923077Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:49.923079Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:51:49.923140Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:49.923214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 0
2023-01-26T10:51:49.923217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::Frontier::0
2023-01-26T10:51:49.923221Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:49.923225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:49.923226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.261271Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.261291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.261304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 0
2023-01-26T10:51:50.261313Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::Homestead::0
2023-01-26T10:51:50.261315Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.261319Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.261321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.261465Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.261472Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.261477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 0
2023-01-26T10:51:50.261479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::EIP150::0
2023-01-26T10:51:50.261481Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.261485Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.261486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.261572Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.261576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.261581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 0
2023-01-26T10:51:50.261583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::EIP158::0
2023-01-26T10:51:50.261585Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.261588Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.261589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.261673Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.261677Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.261681Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 0
2023-01-26T10:51:50.261683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::Byzantium::0
2023-01-26T10:51:50.261686Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.261689Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.261690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.261770Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.261774Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.261779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-26T10:51:50.261781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::Constantinople::0
2023-01-26T10:51:50.261783Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.261786Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.261787Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.261867Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.261871Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.261876Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-26T10:51:50.261878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::ConstantinopleFix::0
2023-01-26T10:51:50.261881Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.261883Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.261884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.261965Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.261969Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.261974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:51:50.261976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::Istanbul::0
2023-01-26T10:51:50.261978Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.261981Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.261982Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.262078Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.262082Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.262087Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:51:50.262089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::Berlin::0
2023-01-26T10:51:50.262093Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.262095Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.262097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.262186Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.262189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.262194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:51:50.262196Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::London::0
2023-01-26T10:51:50.262198Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.262201Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.262203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.262281Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.262285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.262290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:51:50.262292Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_calls"::Merge::0
2023-01-26T10:51:50.262295Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_calls.json"
2023-01-26T10:51:50.262297Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.262299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.262378Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_calls"
2023-01-26T10:51:50.262382Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.264234Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:339.56088ms
2023-01-26T10:51:50.524690Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_callsItself.json", Total Files :: 1
2023-01-26T10:51:50.584079Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:51:50.584269Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:50.584273Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:51:50.584329Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:50.584401Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:51:50.584405Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_callsItself"::London::0
2023-01-26T10:51:50.584408Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_callsItself.json"
2023-01-26T10:51:50.584412Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.584413Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.946808Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_callsItself"
2023-01-26T10:51:50.946821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.946833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:51:50.946839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_callsItself"::Merge::0
2023-01-26T10:51:50.946841Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_callsItself.json"
2023-01-26T10:51:50.946845Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:50.946846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:50.946953Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_callsItself"
2023-01-26T10:51:50.946957Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1526489,
    events_root: None,
}
2023-01-26T10:51:50.948600Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.887097ms
2023-01-26T10:51:51.209248Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json", Total Files :: 1
2023-01-26T10:51:51.247122Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:51:51.247309Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:51.247313Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:51:51.247370Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:51.247373Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:51:51.247435Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:51.247437Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:51:51.247491Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:51.247562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 0
2023-01-26T10:51:51.247566Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Frontier::0
2023-01-26T10:51:51.247569Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247573Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 1
2023-01-26T10:51:51.247576Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Frontier::1
2023-01-26T10:51:51.247578Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247580Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 2
2023-01-26T10:51:51.247583Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Frontier::2
2023-01-26T10:51:51.247585Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247588Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 3
2023-01-26T10:51:51.247591Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Frontier::3
2023-01-26T10:51:51.247593Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247595Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 0
2023-01-26T10:51:51.247598Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Homestead::0
2023-01-26T10:51:51.247600Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247603Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247604Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 1
2023-01-26T10:51:51.247605Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Homestead::1
2023-01-26T10:51:51.247607Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247610Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 2
2023-01-26T10:51:51.247613Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Homestead::2
2023-01-26T10:51:51.247615Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247618Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 3
2023-01-26T10:51:51.247621Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Homestead::3
2023-01-26T10:51:51.247623Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247625Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247627Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 0
2023-01-26T10:51:51.247629Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP150::0
2023-01-26T10:51:51.247631Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247633Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 1
2023-01-26T10:51:51.247636Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP150::1
2023-01-26T10:51:51.247638Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247640Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 2
2023-01-26T10:51:51.247643Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP150::2
2023-01-26T10:51:51.247645Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247647Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 3
2023-01-26T10:51:51.247650Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP150::3
2023-01-26T10:51:51.247652Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247655Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 0
2023-01-26T10:51:51.247657Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP158::0
2023-01-26T10:51:51.247659Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247662Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247663Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 1
2023-01-26T10:51:51.247665Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP158::1
2023-01-26T10:51:51.247667Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247670Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 2
2023-01-26T10:51:51.247674Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP158::2
2023-01-26T10:51:51.247675Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247679Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 3
2023-01-26T10:51:51.247682Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::EIP158::3
2023-01-26T10:51:51.247684Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247686Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 0
2023-01-26T10:51:51.247689Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Byzantium::0
2023-01-26T10:51:51.247692Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247695Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 1
2023-01-26T10:51:51.247700Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Byzantium::1
2023-01-26T10:51:51.247702Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247705Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 2
2023-01-26T10:51:51.247709Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Byzantium::2
2023-01-26T10:51:51.247712Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247716Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 3
2023-01-26T10:51:51.247720Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Byzantium::3
2023-01-26T10:51:51.247722Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247724Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-26T10:51:51.247728Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Constantinople::0
2023-01-26T10:51:51.247729Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247732Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247733Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 1
2023-01-26T10:51:51.247735Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Constantinople::1
2023-01-26T10:51:51.247736Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247740Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 2
2023-01-26T10:51:51.247743Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Constantinople::2
2023-01-26T10:51:51.247745Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247747Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247748Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 3
2023-01-26T10:51:51.247751Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Constantinople::3
2023-01-26T10:51:51.247753Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247756Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-26T10:51:51.247758Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::ConstantinopleFix::0
2023-01-26T10:51:51.247761Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247764Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 1
2023-01-26T10:51:51.247767Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::ConstantinopleFix::1
2023-01-26T10:51:51.247769Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247772Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 2
2023-01-26T10:51:51.247774Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::ConstantinopleFix::2
2023-01-26T10:51:51.247776Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247779Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 3
2023-01-26T10:51:51.247782Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::ConstantinopleFix::3
2023-01-26T10:51:51.247784Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247786Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:51:51.247789Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Istanbul::0
2023-01-26T10:51:51.247791Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247794Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:51:51.247799Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Istanbul::1
2023-01-26T10:51:51.247802Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247805Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247807Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T10:51:51.247809Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Istanbul::2
2023-01-26T10:51:51.247812Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247815Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T10:51:51.247819Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Istanbul::3
2023-01-26T10:51:51.247821Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247823Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247825Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:51:51.247826Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Berlin::0
2023-01-26T10:51:51.247828Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247831Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:51:51.247834Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Berlin::1
2023-01-26T10:51:51.247835Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247838Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T10:51:51.247840Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Berlin::2
2023-01-26T10:51:51.247842Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247845Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T10:51:51.247848Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Berlin::3
2023-01-26T10:51:51.247850Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247852Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247854Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:51:51.247855Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::London::0
2023-01-26T10:51:51.247857Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247861Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247862Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:51:51.247863Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::London::1
2023-01-26T10:51:51.247865Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247868Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:51:51.247871Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::London::2
2023-01-26T10:51:51.247873Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247876Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247877Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:51:51.247879Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::London::3
2023-01-26T10:51:51.247881Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247883Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.247885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:51:51.247886Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Merge::0
2023-01-26T10:51:51.247888Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247891Z  WARN evm_eth_compliance::statetest::runner: TX len : 1
2023-01-26T10:51:51.247892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:51:51.247895Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Merge::1
2023-01-26T10:51:51.247897Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247901Z  WARN evm_eth_compliance::statetest::runner: TX len : 5
2023-01-26T10:51:51.247903Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:51:51.247905Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Merge::2
2023-01-26T10:51:51.247908Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247912Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T10:51:51.247914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:51:51.247917Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "transactionCollidingWithNonEmptyAccount_init"::Merge::3
2023-01-26T10:51:51.247919Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_init.json"
2023-01-26T10:51:51.247923Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:51:51.248722Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:806.909s
2023-01-26T10:51:51.498989Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_send.json", Total Files :: 1
2023-01-26T10:51:51.539161Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:51:51.539339Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:51.539343Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:51:51.539394Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:51.539396Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:51:51.539454Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:51:51.539527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:51:51.539530Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_send"::London::0
2023-01-26T10:51:51.539534Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_send.json"
2023-01-26T10:51:51.539538Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:51.539540Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:51.887153Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_send"
2023-01-26T10:51:51.887170Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T10:51:51.887181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:51:51.887187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "transactionCollidingWithNonEmptyAccount_send"::Merge::0
2023-01-26T10:51:51.887189Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stEIP3607/transactionCollidingWithNonEmptyAccount_send.json"
2023-01-26T10:51:51.887192Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:51:51.887194Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:51:51.887308Z  INFO evm_eth_compliance::statetest::runner: UC : "transactionCollidingWithNonEmptyAccount_send"
2023-01-26T10:51:51.887313Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T10:51:51.888856Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:348.16081ms
```
