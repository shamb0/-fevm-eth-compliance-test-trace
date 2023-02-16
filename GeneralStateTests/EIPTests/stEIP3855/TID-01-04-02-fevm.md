
> Command Executed

```
clear && \
	RUST_LOG=revme=trace \
	cargo run --release -p revme \
	-- \
	statetest \
	-s ./bins/revme/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json
```

> Execution Trace

```
2023-02-16T10:13:31.413704Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json", Total Files :: 1
2023-02-16T10:13:31.413970Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-16T10:13:31.442114Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-16T10:13:31.442251Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442255Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-16T10:13:31.442324Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442326Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-16T10:13:31.442398Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442400Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-02-16T10:13:31.442451Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442454Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-02-16T10:13:31.442513Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442515Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 5
2023-02-16T10:13:31.442584Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442586Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 6
2023-02-16T10:13:31.442646Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442648Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 7
2023-02-16T10:13:31.442703Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442706Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 8
2023-02-16T10:13:31.442755Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-16T10:13:31.442825Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-16T10:13:31.442828Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "push0"::Merge::0
2023-02-16T10:13:31.442831Z  INFO evm_eth_compliance::statetest::executor: Path : "mod-push0.json"
2023-02-16T10:13:31.442833Z  INFO evm_eth_compliance::statetest::executor: TX len : 20
2023-02-16T10:13:31.782380Z  INFO evm_eth_compliance::statetest::executor: Post Hash Check ::
2023-02-16T10:13:31.782407Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782413Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782425Z  INFO evm_eth_compliance::common::tester: slots :: [
    (
        0x0000000000000000000000000000000000000000000000000000000000000001,
        b"\x01",
    ),
]
2023-02-16T10:13:31.782435Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b20af75e120bc9b2b813d81494fcb57703dcd277a3dab4cefbfb6e8188c
2023-02-16T10:13:31.782440Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782444Z  INFO evm_eth_compliance::common::tester: balance :: 6571924981564438
2023-02-16T10:13:31.782449Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782453Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b20c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad804
2023-02-16T10:13:31.782456Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782459Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782462Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782465Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b20cc61b581b699b895ad2557e2aa9578bcf05d163d6c03a900a38e312b
2023-02-16T10:13:31.782468Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782470Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782473Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782476Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b200125401e1ab3861d0d9dd8099943b70a1fd558be51c551394387321c
2023-02-16T10:13:31.782479Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782481Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782484Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782487Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b20a44ddbe3846599b1b2ca0594fb0cb0c2d6d63b877ce5ddb234339190
2023-02-16T10:13:31.782490Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782492Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782495Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782498Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b2048191a2b9cc0ce9f46786b06bc6b47348b83d5e37b8bde367268384d
2023-02-16T10:13:31.782501Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782503Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782507Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782510Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b20edcea87ee48aa9a04c103b5b3c70ed9ff9fe2588bd460852de66d194
2023-02-16T10:13:31.782513Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782515Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782518Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782521Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b20fd9bdc48c415ec6f74ded272c8758e673376fc007812223384f6eea1
2023-02-16T10:13:31.782524Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-16T10:13:31.782526Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-16T10:13:31.782530Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-16T10:13:31.782532Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 1b221b2029c955fec03398c668c9f67fcd2c1d24e301c426a12737ce10c33113
2023-02-16T10:13:31.782561Z  INFO evm_eth_compliance::statetest::executor: Calc :: 0x07c4f5ee36de88e4641a6bba884183a8a7d540302c34d53f3aef0e47d345edd7
2023-02-16T10:13:31.782564Z  INFO evm_eth_compliance::statetest::executor: Actual :: 0x84893d9a4161a9cf913c9c53a1827b7a3abfa2f0b57216e605b7cb87f527ae72
2023-02-16T10:13:31.782572Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4366068,
    events_root: None,
}
2023-02-16T10:13:31.783780Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-16T10:13:31.783925Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:340.478302ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "mod-push0.json::push0": [
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
```