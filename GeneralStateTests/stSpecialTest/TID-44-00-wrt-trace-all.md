> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stSpecialTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stSpecialTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution Looks OK, all use-cases passed.

> Execution Trace

```
2023-01-24T14:16:15.368244Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/FailedCreateRevertsDeletion.json", Total Files :: 1
2023-01-24T14:16:15.396394Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:15.396590Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:15.396594Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:15.396648Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:15.396717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:15.396720Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "FailedCreateRevertsDeletion"::Istanbul::0
2023-01-24T14:16:15.396723Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/FailedCreateRevertsDeletion.json"
2023-01-24T14:16:15.396726Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T14:16:15.396728Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:15.396730Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "FailedCreateRevertsDeletion"::Berlin::0
2023-01-24T14:16:15.396732Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/FailedCreateRevertsDeletion.json"
2023-01-24T14:16:15.396734Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T14:16:15.396736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:15.396738Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "FailedCreateRevertsDeletion"::London::0
2023-01-24T14:16:15.396740Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/FailedCreateRevertsDeletion.json"
2023-01-24T14:16:15.396742Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T14:16:15.396743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:15.396745Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "FailedCreateRevertsDeletion"::Merge::0
2023-01-24T14:16:15.396747Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/FailedCreateRevertsDeletion.json"
2023-01-24T14:16:15.396749Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T14:16:15.397387Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.626s
2023-01-24T14:16:15.647272Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_Attack.json", Total Files :: 1
2023-01-24T14:16:15.675143Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:15.675378Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:15.675381Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:15.675434Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:15.675502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:15.675505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_Attack"::Istanbul::0
2023-01-24T14:16:15.675508Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_Attack.json"
2023-01-24T14:16:15.675510Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:15.675512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:16.286311Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510900052,
    events_root: None,
}
2023-01-24T14:16:16.289651Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:16.289664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_Attack"::Berlin::0
2023-01-24T14:16:16.289667Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_Attack.json"
2023-01-24T14:16:16.289673Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:16.289674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:16.546877Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510900052,
    events_root: None,
}
2023-01-24T14:16:16.551078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:16.551089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_Attack"::London::0
2023-01-24T14:16:16.551092Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_Attack.json"
2023-01-24T14:16:16.551095Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:16.551097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:16.804662Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510900052,
    events_root: None,
}
2023-01-24T14:16:16.809194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:16.809207Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_Attack"::Merge::0
2023-01-24T14:16:16.809210Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_Attack.json"
2023-01-24T14:16:16.809213Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:16.809217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:17.060405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510900052,
    events_root: None,
}
2023-01-24T14:16:17.078911Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.390074155s
2023-01-24T14:16:17.347194Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_AttackwithJump.json", Total Files :: 1
2023-01-24T14:16:17.375297Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:17.375538Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:17.375541Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:17.375595Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:17.375663Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:17.375667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_AttackwithJump"::Istanbul::0
2023-01-24T14:16:17.375669Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_AttackwithJump.json"
2023-01-24T14:16:17.375672Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:17.375674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:17.977491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3512613818,
    events_root: None,
}
2023-01-24T14:16:17.980826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:17.980839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_AttackwithJump"::Berlin::0
2023-01-24T14:16:17.980841Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_AttackwithJump.json"
2023-01-24T14:16:17.980845Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:17.980846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:18.242644Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3512613818,
    events_root: None,
}
2023-01-24T14:16:18.246647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:18.246661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_AttackwithJump"::London::0
2023-01-24T14:16:18.246664Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_AttackwithJump.json"
2023-01-24T14:16:18.246668Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:18.246669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:18.505788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3512613818,
    events_root: None,
}
2023-01-24T14:16:18.510454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:18.510468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "JUMPDEST_AttackwithJump"::Merge::0
2023-01-24T14:16:18.510471Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/JUMPDEST_AttackwithJump.json"
2023-01-24T14:16:18.510474Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:18.510475Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:18.769342Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3512613818,
    events_root: None,
}
2023-01-24T14:16:18.787292Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.398268693s
2023-01-24T14:16:19.041151Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/OverflowGasMakeMoney.json", Total Files :: 1
2023-01-24T14:16:19.069761Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:19.069954Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.070025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:19.070029Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "OverflowGasMakeMoney"::Istanbul::0
2023-01-24T14:16:19.070032Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/OverflowGasMakeMoney.json"
2023-01-24T14:16:19.070035Z  WARN evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:19.070036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:19.070038Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "OverflowGasMakeMoney"::Berlin::0
2023-01-24T14:16:19.070040Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/OverflowGasMakeMoney.json"
2023-01-24T14:16:19.070042Z  WARN evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:19.070043Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:19.070045Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "OverflowGasMakeMoney"::London::0
2023-01-24T14:16:19.070046Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/OverflowGasMakeMoney.json"
2023-01-24T14:16:19.070049Z  WARN evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:19.070050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:19.070052Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "OverflowGasMakeMoney"::Merge::0
2023-01-24T14:16:19.070054Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/OverflowGasMakeMoney.json"
2023-01-24T14:16:19.070056Z  WARN evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:19.070683Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:301.285s
2023-01-24T14:16:19.318757Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/StackDepthLimitSEC.json", Total Files :: 1
2023-01-24T14:16:19.347600Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:19.347789Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.347860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:19.347863Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "StackDepthLimitSEC"::Istanbul::0
2023-01-24T14:16:19.347866Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/StackDepthLimitSEC.json"
2023-01-24T14:16:19.347869Z  WARN evm_eth_compliance::statetest::runner: TX len : 53
2023-01-24T14:16:19.347871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:19.347872Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "StackDepthLimitSEC"::Berlin::0
2023-01-24T14:16:19.347874Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/StackDepthLimitSEC.json"
2023-01-24T14:16:19.347876Z  WARN evm_eth_compliance::statetest::runner: TX len : 53
2023-01-24T14:16:19.347878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:19.347879Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "StackDepthLimitSEC"::London::0
2023-01-24T14:16:19.347881Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/StackDepthLimitSEC.json"
2023-01-24T14:16:19.347883Z  WARN evm_eth_compliance::statetest::runner: TX len : 53
2023-01-24T14:16:19.347885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:19.347886Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "StackDepthLimitSEC"::Merge::0
2023-01-24T14:16:19.347889Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/StackDepthLimitSEC.json"
2023-01-24T14:16:19.347891Z  WARN evm_eth_compliance::statetest::runner: TX len : 53
2023-01-24T14:16:19.348533Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:296.125s
2023-01-24T14:16:19.609273Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/block504980.json", Total Files :: 1
2023-01-24T14:16:19.638037Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:19.638229Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638233Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:19.638288Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638290Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T14:16:19.638349Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638351Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T14:16:19.638403Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638405Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T14:16:19.638454Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638456Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T14:16:19.638549Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638551Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T14:16:19.638603Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638605Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-24T14:16:19.638647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638649Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-24T14:16:19.638705Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638707Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-24T14:16:19.638762Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638764Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-24T14:16:19.638808Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638810Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-24T14:16:19.638861Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638863Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-24T14:16:19.638915Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.638917Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-24T14:16:19.638971Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:19.639041Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:19.639044Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "block504980"::Istanbul::0
2023-01-24T14:16:19.639047Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/block504980.json"
2023-01-24T14:16:19.639050Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:19.639051Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:19.999063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff },
    gas_used: 280622536,
    events_root: None,
}
2023-01-24T14:16:19.999361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:19.999368Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "block504980"::Berlin::0
2023-01-24T14:16:19.999370Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/block504980.json"
2023-01-24T14:16:19.999373Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:19.999375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.018249Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff },
    gas_used: 280622536,
    events_root: None,
}
2023-01-24T14:16:20.018534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:20.018537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "block504980"::London::0
2023-01-24T14:16:20.018539Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/block504980.json"
2023-01-24T14:16:20.018542Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.018543Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.037225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff },
    gas_used: 280622536,
    events_root: None,
}
2023-01-24T14:16:20.037513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:20.037517Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "block504980"::Merge::0
2023-01-24T14:16:20.037518Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/block504980.json"
2023-01-24T14:16:20.037521Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.037522Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.056441Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff },
    gas_used: 280622536,
    events_root: None,
}
2023-01-24T14:16:20.058611Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:418.7483ms
2023-01-24T14:16:20.314751Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/deploymentError.json", Total Files :: 1
2023-01-24T14:16:20.342843Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:20.343029Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.343099Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:20.343102Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "deploymentError"::Istanbul::0
2023-01-24T14:16:20.343105Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/deploymentError.json"
2023-01-24T14:16:20.343108Z  WARN evm_eth_compliance::statetest::runner: TX len : 4195
2023-01-24T14:16:20.343110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:20.343111Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "deploymentError"::Berlin::0
2023-01-24T14:16:20.343113Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/deploymentError.json"
2023-01-24T14:16:20.343117Z  WARN evm_eth_compliance::statetest::runner: TX len : 4195
2023-01-24T14:16:20.343118Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:20.343119Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "deploymentError"::London::0
2023-01-24T14:16:20.343121Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/deploymentError.json"
2023-01-24T14:16:20.343124Z  WARN evm_eth_compliance::statetest::runner: TX len : 4195
2023-01-24T14:16:20.343126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:20.343127Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "deploymentError"::Merge::0
2023-01-24T14:16:20.343129Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/deploymentError.json"
2023-01-24T14:16:20.343133Z  WARN evm_eth_compliance::statetest::runner: TX len : 4195
2023-01-24T14:16:20.343689Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:295.294s
2023-01-24T14:16:20.595422Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json", Total Files :: 1
2023-01-24T14:16:20.624150Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:20.624349Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.624353Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:20.624412Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.624416Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T14:16:20.624480Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.624483Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T14:16:20.624538Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.624541Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T14:16:20.624593Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.624595Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-24T14:16:20.624652Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.624654Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-24T14:16:20.624713Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:20.624802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:20.624805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::0
2023-01-24T14:16:20.624809Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.624812Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.624815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.982377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 23224308,
    events_root: None,
}
2023-01-24T14:16:20.982416Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T14:16:20.982422Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::1
2023-01-24T14:16:20.982425Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.982428Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.982429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.983049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16879959,
    events_root: None,
}
2023-01-24T14:16:20.983071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:20.983074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::0
2023-01-24T14:16:20.983076Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.983078Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.983080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.983621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11687820,
    events_root: None,
}
2023-01-24T14:16:20.983635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T14:16:20.983637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::1
2023-01-24T14:16:20.983639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.983642Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.983643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.984193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11860795,
    events_root: None,
}
2023-01-24T14:16:20.984207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:20.984210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::0
2023-01-24T14:16:20.984212Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.984214Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.984216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.984755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11687820,
    events_root: None,
}
2023-01-24T14:16:20.984769Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T14:16:20.984771Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::1
2023-01-24T14:16:20.984773Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.984776Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.984777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.985324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11860795,
    events_root: None,
}
2023-01-24T14:16:20.985337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:20.985340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::0
2023-01-24T14:16:20.985342Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.985344Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.985345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.985880Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11687820,
    events_root: None,
}
2023-01-24T14:16:20.985894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T14:16:20.985896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::London::1
2023-01-24T14:16:20.985898Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.985901Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.985902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.986442Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11860795,
    events_root: None,
}
2023-01-24T14:16:20.986457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:20.986459Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::0
2023-01-24T14:16:20.986461Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.986463Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.986465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.987003Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11687820,
    events_root: None,
}
2023-01-24T14:16:20.987017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T14:16:20.987020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::1
2023-01-24T14:16:20.987022Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.987024Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.987025Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.987574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11860795,
    events_root: None,
}
2023-01-24T14:16:20.987588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:20.987591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::0
2023-01-24T14:16:20.987593Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.987595Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.987596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.988140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11687820,
    events_root: None,
}
2023-01-24T14:16:20.988153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T14:16:20.988156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::1
2023-01-24T14:16:20.988158Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.988160Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.988162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.988703Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11860795,
    events_root: None,
}
2023-01-24T14:16:20.988717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:20.988719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::0
2023-01-24T14:16:20.988721Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.988723Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.988725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.989262Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11687820,
    events_root: None,
}
2023-01-24T14:16:20.989276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T14:16:20.989279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::1
2023-01-24T14:16:20.989280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.989283Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.989284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.989820Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11860795,
    events_root: None,
}
2023-01-24T14:16:20.989834Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:20.989837Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::0
2023-01-24T14:16:20.989839Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.989841Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.989843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.990382Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11687820,
    events_root: None,
}
2023-01-24T14:16:20.990396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T14:16:20.990399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eoaEmpty"::Merge::1
2023-01-24T14:16:20.990400Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/eoaEmpty.json"
2023-01-24T14:16:20.990403Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T14:16:20.990404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:20.990945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11860795,
    events_root: None,
}
2023-01-24T14:16:20.992330Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.814151ms
2023-01-24T14:16:21.248560Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/failed_tx_xcf416c53.json", Total Files :: 1
2023-01-24T14:16:21.276765Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:21.276955Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:21.276959Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:21.277013Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:21.277015Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T14:16:21.277074Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:21.277144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:21.277147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "failed_tx_xcf416c53"::Istanbul::0
2023-01-24T14:16:21.277150Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/failed_tx_xcf416c53.json"
2023-01-24T14:16:21.277153Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T14:16:21.277154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000009
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error IncorrectInputSize
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000010
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000011
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000012
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000013
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000014
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000015
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000016
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000017
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000018
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000019
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000020
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000021
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000022
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000023
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000024
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000025
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000026
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000027
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000028
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000029
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000030
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000031
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000032
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000033
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000034
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000035
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000036
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000037
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000038
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000039
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000040
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000041
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000042
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000043
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000044
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000045
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000046
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000047
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000048
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000049
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000050
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000051
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000052
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000053
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000054
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000055
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000056
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000057
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000058
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000059
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000060
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000061
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000062
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000063
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000064
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000065
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000066
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000067
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000068
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000069
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000070
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000071
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000072
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000073
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000074
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000075
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000076
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000077
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000078
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000079
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000080
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000081
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000082
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000083
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000084
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000085
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000086
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000087
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000088
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000089
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000090
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000091
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000092
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000093
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000094
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000095
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000096
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000097
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000098
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000099
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000aa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ab
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ac
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ad
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ae
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000af
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ba
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000be
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ca
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ce
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000da
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000db
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000de
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000df
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ea
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000eb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ec
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ed
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ee
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ef
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fe
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ff
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:21.662039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 49172529,
    events_root: None,
}
2023-01-24T14:16:21.662134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:21.662140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "failed_tx_xcf416c53"::Berlin::0
2023-01-24T14:16:21.662143Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/failed_tx_xcf416c53.json"
2023-01-24T14:16:21.662146Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T14:16:21.662147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000009
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error IncorrectInputSize
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000010
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000011
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000012
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000013
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000014
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000015
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000016
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000017
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000018
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000019
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000020
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000021
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000022
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000023
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000024
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000025
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000026
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000027
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000028
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000029
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000030
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000031
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000032
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000033
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000034
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000035
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000036
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000037
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000038
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000039
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000040
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000041
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000042
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000043
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000044
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000045
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000046
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000047
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000048
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000049
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000050
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000051
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000052
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000053
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000054
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000055
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000056
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000057
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000058
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000059
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000060
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000061
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000062
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000063
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000064
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000065
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000066
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000067
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000068
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000069
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000070
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000071
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000072
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000073
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000074
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000075
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000076
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000077
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000078
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000079
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000080
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000081
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000082
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000083
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000084
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000085
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000086
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000087
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000088
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000089
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000090
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000091
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000092
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000093
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000094
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000095
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000096
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000097
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000098
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000099
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000aa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ab
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ac
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ad
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ae
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000af
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ba
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000be
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ca
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ce
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000da
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000db
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000de
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000df
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ea
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000eb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ec
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ed
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ee
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ef
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fe
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ff
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:21.668838Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 49172529,
    events_root: None,
}
2023-01-24T14:16:21.668926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:21.668929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "failed_tx_xcf416c53"::London::0
2023-01-24T14:16:21.668931Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/failed_tx_xcf416c53.json"
2023-01-24T14:16:21.668934Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T14:16:21.668935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000009
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error IncorrectInputSize
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000010
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000011
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000012
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000013
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000014
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000015
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000016
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000017
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000018
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000019
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000020
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000021
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000022
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000023
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000024
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000025
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000026
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000027
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000028
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000029
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000030
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000031
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000032
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000033
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000034
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000035
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000036
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000037
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000038
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000039
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000040
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000041
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000042
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000043
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000044
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000045
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000046
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000047
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000048
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000049
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000050
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000051
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000052
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000053
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000054
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000055
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000056
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000057
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000058
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000059
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000060
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000061
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000062
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000063
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000064
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000065
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000066
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000067
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000068
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000069
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000070
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000071
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000072
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000073
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000074
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000075
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000076
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000077
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000078
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000079
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000080
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000081
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000082
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000083
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000084
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000085
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000086
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000087
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000088
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000089
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000090
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000091
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000092
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000093
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000094
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000095
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000096
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000097
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000098
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000099
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000aa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ab
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ac
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ad
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ae
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000af
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ba
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000be
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ca
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ce
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000da
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000db
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000de
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000df
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ea
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000eb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ec
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ed
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ee
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ef
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fe
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ff
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:21.675612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 49172529,
    events_root: None,
}
2023-01-24T14:16:21.675702Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:21.675706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "failed_tx_xcf416c53"::Merge::0
2023-01-24T14:16:21.675708Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/failed_tx_xcf416c53.json"
2023-01-24T14:16:21.675711Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T14:16:21.675713Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000001
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000004
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000005
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000006
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000007
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error EcErr(InvalidEncoding)
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000008
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000009
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[WARN] Precompile failed: error IncorrectInputSize
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000000f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000010
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000011
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000012
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000013
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000014
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000015
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000016
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000017
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000018
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000019
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000001f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000020
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000021
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000022
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000023
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000024
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000025
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000026
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000027
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000028
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000029
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000002f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000030
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000031
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000032
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000033
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000034
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000035
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000036
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000037
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000038
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000039
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000003f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000040
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000041
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000042
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000043
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000044
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000045
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000046
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000047
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000048
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000049
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000004f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000050
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000051
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000052
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000053
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000054
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000055
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000056
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000057
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000058
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000059
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000005f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000060
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000061
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000062
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000063
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000064
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000065
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000066
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000067
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000068
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000069
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000006f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000070
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000071
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000072
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000073
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000074
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000075
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000076
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000077
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000078
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000079
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000007f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000080
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000081
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000082
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000083
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000084
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000085
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000086
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000087
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000088
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000089
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000008f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000090
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000091
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000092
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000093
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000094
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000095
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000096
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000097
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000098
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000099
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009a
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009b
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009c
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009d
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009e
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 000000000000000000000000000000000000009f
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000a9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000aa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ab
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ac
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ad
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ae
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000af
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000b9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ba
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000be
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000bf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000c9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ca
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ce
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cf
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000d9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000da
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000db
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000de
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000df
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000e9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ea
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000eb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ec
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ed
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ee
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ef
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f0
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f1
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f2
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f3
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f4
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f5
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f6
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f7
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f8
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000f9
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fa
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fb
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000fe
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000ff
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:21.682791Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 49172529,
    events_root: None,
}
2023-01-24T14:16:21.684523Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:406.122515ms
2023-01-24T14:16:21.942186Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/gasPrice0.json", Total Files :: 1
2023-01-24T14:16:21.970763Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:21.970960Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:21.970963Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:21.971019Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:21.971088Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:21.971091Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gasPrice0"::Istanbul::0
2023-01-24T14:16:21.971093Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/gasPrice0.json"
2023-01-24T14:16:21.971097Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:21.971099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.328028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2453083,
    events_root: None,
}
2023-01-24T14:16:22.328049Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:22.328056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gasPrice0"::Berlin::0
2023-01-24T14:16:22.328058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/gasPrice0.json"
2023-01-24T14:16:22.328061Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:22.328062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.328186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557385,
    events_root: None,
}
2023-01-24T14:16:22.328193Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:22.328195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gasPrice0"::London::0
2023-01-24T14:16:22.328197Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/gasPrice0.json"
2023-01-24T14:16:22.328199Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:22.328201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.328284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557385,
    events_root: None,
}
2023-01-24T14:16:22.328290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:22.328293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gasPrice0"::Merge::0
2023-01-24T14:16:22.328295Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/gasPrice0.json"
2023-01-24T14:16:22.328297Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:22.328298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.328380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557385,
    events_root: None,
}
2023-01-24T14:16:22.329895Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.627402ms
2023-01-24T14:16:22.585979Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/makeMoney.json", Total Files :: 1
2023-01-24T14:16:22.617417Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:22.617625Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:22.617629Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:22.617683Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:22.617685Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T14:16:22.617743Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:22.617812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:22.617816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "makeMoney"::Istanbul::0
2023-01-24T14:16:22.617819Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/makeMoney.json"
2023-01-24T14:16:22.617823Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:22.617824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.971048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4668849,
    events_root: None,
}
2023-01-24T14:16:22.971075Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:22.971082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "makeMoney"::Berlin::0
2023-01-24T14:16:22.971085Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/makeMoney.json"
2023-01-24T14:16:22.971087Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:22.971089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.971303Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3518355,
    events_root: None,
}
2023-01-24T14:16:22.971315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:22.971317Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "makeMoney"::London::0
2023-01-24T14:16:22.971319Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/makeMoney.json"
2023-01-24T14:16:22.971321Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:22.971322Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.971507Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3518355,
    events_root: None,
}
2023-01-24T14:16:22.971518Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:22.971520Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "makeMoney"::Merge::0
2023-01-24T14:16:22.971522Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/makeMoney.json"
2023-01-24T14:16:22.971525Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:22.971526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:22.971705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3518355,
    events_root: None,
}
2023-01-24T14:16:22.973280Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.304162ms
2023-01-24T14:16:23.232920Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/push32withoutByte.json", Total Files :: 1
2023-01-24T14:16:23.262582Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:23.262777Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:23.262781Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:23.262834Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:23.262904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:23.262907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push32withoutByte"::Istanbul::0
2023-01-24T14:16:23.262910Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/push32withoutByte.json"
2023-01-24T14:16:23.262913Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:23.262915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:23.618050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1524041,
    events_root: None,
}
2023-01-24T14:16:23.618073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:23.618080Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push32withoutByte"::Berlin::0
2023-01-24T14:16:23.618083Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/push32withoutByte.json"
2023-01-24T14:16:23.618086Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:23.618087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:23.618203Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1524041,
    events_root: None,
}
2023-01-24T14:16:23.618209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:23.618212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push32withoutByte"::London::0
2023-01-24T14:16:23.618214Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/push32withoutByte.json"
2023-01-24T14:16:23.618216Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:23.618218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:23.618295Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1524041,
    events_root: None,
}
2023-01-24T14:16:23.618302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:23.618304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push32withoutByte"::Merge::0
2023-01-24T14:16:23.618306Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/push32withoutByte.json"
2023-01-24T14:16:23.618308Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:23.618310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:23.618385Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1524041,
    events_root: None,
}
2023-01-24T14:16:23.619775Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.815149ms
2023-01-24T14:16:23.893023Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/selfdestructEIP2929.json", Total Files :: 1
2023-01-24T14:16:23.923375Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:23.923575Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:23.923578Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:23.923632Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:23.923634Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T14:16:23.923694Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:23.923695Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T14:16:23.923742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:23.923744Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T14:16:23.923801Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:23.923889Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:23.923893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "selfdestructEIP2929"::Istanbul::0
2023-01-24T14:16:23.923896Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/selfdestructEIP2929.json"
2023-01-24T14:16:23.923900Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:23.923902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:24.287755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 37559813,
    events_root: None,
}
2023-01-24T14:16:24.287811Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:24.287818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "selfdestructEIP2929"::Berlin::0
2023-01-24T14:16:24.287820Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/selfdestructEIP2929.json"
2023-01-24T14:16:24.287823Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:24.287825Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:24.288837Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15804896,
    events_root: None,
}
2023-01-24T14:16:24.288871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:24.288874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "selfdestructEIP2929"::London::0
2023-01-24T14:16:24.288876Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/selfdestructEIP2929.json"
2023-01-24T14:16:24.288878Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:24.288880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:24.289866Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15804896,
    events_root: None,
}
2023-01-24T14:16:24.289899Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:24.289902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "selfdestructEIP2929"::Merge::0
2023-01-24T14:16:24.289904Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/selfdestructEIP2929.json"
2023-01-24T14:16:24.289906Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:24.289908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000cc
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 00000000000000000000000000000000000000dd
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
[INFO] Call Precompile:
	address: 0000000000000000000000000000000000000003
	context: PrecompileContext { call_type: Call, gas_limit: 0, value: 0 }
	input:
2023-01-24T14:16:24.290878Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15804896,
    events_root: None,
}
2023-01-24T14:16:24.292415Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.540866ms
2023-01-24T14:16:24.547539Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/sha3_deja.json", Total Files :: 1
2023-01-24T14:16:24.576157Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:24.576347Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:24.576350Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:24.576404Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:24.576472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:24.576475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3_deja"::Istanbul::0
2023-01-24T14:16:24.576478Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/sha3_deja.json"
2023-01-24T14:16:24.576481Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:24.576482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:24.911050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544903,
    events_root: None,
}
2023-01-24T14:16:24.911072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:24.911081Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3_deja"::Berlin::0
2023-01-24T14:16:24.911084Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/sha3_deja.json"
2023-01-24T14:16:24.911087Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:24.911089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:24.911210Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544903,
    events_root: None,
}
2023-01-24T14:16:24.911219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:24.911222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3_deja"::London::0
2023-01-24T14:16:24.911224Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/sha3_deja.json"
2023-01-24T14:16:24.911228Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:24.911230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:24.911315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544903,
    events_root: None,
}
2023-01-24T14:16:24.911324Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:24.911327Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3_deja"::Merge::0
2023-01-24T14:16:24.911330Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/sha3_deja.json"
2023-01-24T14:16:24.911333Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T14:16:24.911335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:24.911419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544903,
    events_root: None,
}
2023-01-24T14:16:24.912995Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:335.275912ms
2023-01-24T14:16:25.168494Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSpecialTest/tx_e1c174e2.json", Total Files :: 1
2023-01-24T14:16:25.198676Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T14:16:25.198905Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:25.198909Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T14:16:25.198962Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T14:16:25.199034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T14:16:25.199037Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tx_e1c174e2"::Istanbul::0
2023-01-24T14:16:25.199040Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/tx_e1c174e2.json"
2023-01-24T14:16:25.199044Z  INFO evm_eth_compliance::statetest::runner: TX len : 196
2023-01-24T14:16:25.199046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:25.547586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000029 },
    gas_used: 2796286,
    events_root: None,
}
2023-01-24T14:16:25.547609Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T14:16:25.547616Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tx_e1c174e2"::Berlin::0
2023-01-24T14:16:25.547618Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/tx_e1c174e2.json"
2023-01-24T14:16:25.547621Z  INFO evm_eth_compliance::statetest::runner: TX len : 196
2023-01-24T14:16:25.547623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:25.547848Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000029 },
    gas_used: 2796286,
    events_root: None,
}
2023-01-24T14:16:25.547857Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T14:16:25.547859Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tx_e1c174e2"::London::0
2023-01-24T14:16:25.547861Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/tx_e1c174e2.json"
2023-01-24T14:16:25.547863Z  INFO evm_eth_compliance::statetest::runner: TX len : 196
2023-01-24T14:16:25.547865Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:25.548063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000029 },
    gas_used: 2796286,
    events_root: None,
}
2023-01-24T14:16:25.548072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T14:16:25.548074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "tx_e1c174e2"::Merge::0
2023-01-24T14:16:25.548076Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSpecialTest/tx_e1c174e2.json"
2023-01-24T14:16:25.548078Z  INFO evm_eth_compliance::statetest::runner: TX len : 196
2023-01-24T14:16:25.548080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T14:16:25.548276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000029 },
    gas_used: 2796286,
    events_root: None,
}
2023-01-24T14:16:25.549836Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.613297ms
```
