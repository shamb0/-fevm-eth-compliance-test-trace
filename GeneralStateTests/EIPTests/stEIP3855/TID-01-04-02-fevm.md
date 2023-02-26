
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
2023-02-17T07:06:11.816947Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json", Total Files :: 1
2023-02-17T07:06:11.817291Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-17T07:06:11.847552Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-17T07:06:11.847698Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.847702Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-17T07:06:11.847784Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.847788Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-17T07:06:11.847864Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.847867Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-02-17T07:06:11.847927Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.847929Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-02-17T07:06:11.847994Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.847996Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 5
2023-02-17T07:06:11.848067Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.848070Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 6
2023-02-17T07:06:11.848131Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.848133Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 7
2023-02-17T07:06:11.848189Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.848191Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 8
2023-02-17T07:06:11.848242Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-17T07:06:11.848315Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-17T07:06:11.848317Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "push0"::Merge::0
2023-02-17T07:06:11.848320Z  INFO evm_eth_compliance::statetest::executor: Path : "mod-push0.json"
2023-02-17T07:06:11.848322Z  INFO evm_eth_compliance::statetest::executor: TX len : 20
2023-02-17T07:06:12.191437Z  INFO evm_eth_compliance::statetest::executor: Post Hash Check ::
2023-02-17T07:06:12.191453Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000600"
2023-02-17T07:06:12.191465Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191469Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191475Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-17T07:06:12.191478Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: fd9bdc48c415ec6f74ded272c8758e673376fc007812223384f6eea1588dab60
2023-02-17T07:06:12.191480Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000100"
2023-02-17T07:06:12.191483Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191484Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191487Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-17T07:06:12.191489Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 0125401e1ab3861d0d9dd8099943b70a1fd558be51c551394387321c48cf5d97
2023-02-17T07:06:12.191490Z  INFO evm_eth_compliance::statetest::executor: State info for => "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-17T07:06:12.191493Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191496Z  INFO evm_eth_compliance::common::tester: balance :: 17592186044416
2023-02-17T07:06:12.191499Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-17T07:06:12.191501Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
2023-02-17T07:06:12.191503Z  INFO evm_eth_compliance::statetest::executor: State info for => "b94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-17T07:06:12.191508Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191509Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191515Z  INFO evm_eth_compliance::common::tester: slots :: [
    (
        0x0000000000000000000000000000000000000000000000000000000000000001,
        b"\x01",
    ),
]
2023-02-17T07:06:12.191522Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: af75e120bc9b2b813d81494fcb57703dcd277a3dab4cefbfb6e8188c8c101d6b
2023-02-17T07:06:12.191524Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000700"
2023-02-17T07:06:12.191527Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191529Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191531Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-17T07:06:12.191533Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 29c955fec03398c668c9f67fcd2c1d24e301c426a12737ce10c33113443a8410
2023-02-17T07:06:12.191534Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000500"
2023-02-17T07:06:12.191537Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191539Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191541Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-17T07:06:12.191543Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: edcea87ee48aa9a04c103b5b3c70ed9ff9fe2588bd460852de66d194439bd683
2023-02-17T07:06:12.191544Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000300"
2023-02-17T07:06:12.191547Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191549Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191552Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-17T07:06:12.191554Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: cc61b581b699b895ad2557e2aa9578bcf05d163d6c03a900a38e312bdfc2f79b
2023-02-17T07:06:12.191555Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000400"
2023-02-17T07:06:12.191559Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191560Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191569Z  INFO evm_eth_compliance::common::tester: slots :: [
    (
        0x0000000000000000000000000000000000000000000000000000000000000000,
        b"\n",
    ),
    (
        0x0000000000000000000000000000000000000000000000000000000000000001,
        b"\n",
    ),
]
2023-02-17T07:06:12.191576Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: 48191a2b9cc0ce9f46786b06bc6b47348b83d5e37b8bde367268384d07df718b
2023-02-17T07:06:12.191578Z  INFO evm_eth_compliance::statetest::executor: State info for => "0000000000000000000000000000000000000200"
2023-02-17T07:06:12.191580Z  INFO evm_eth_compliance::common::tester: nonce :: 0
2023-02-17T07:06:12.191582Z  INFO evm_eth_compliance::common::tester: balance :: 0
2023-02-17T07:06:12.191584Z  INFO evm_eth_compliance::common::tester: slots :: []
2023-02-17T07:06:12.191586Z  INFO evm_eth_compliance::common::tester: bytecode_hash.0 :: a44ddbe3846599b1b2ca0594fb0cb0c2d6d63b877ce5ddb234339190f6535058
2023-02-17T07:06:12.191608Z  INFO evm_eth_compliance::statetest::executor: Calc :: 0xa749ef084d880aee91e425593f6526dddfacea89ad64b01f8c85abafd8dd1fdf
2023-02-17T07:06:12.191611Z  INFO evm_eth_compliance::statetest::executor: Actual :: 0x84893d9a4161a9cf913c9c53a1827b7a3abfa2f0b57216e605b7cb87f527ae72
2023-02-17T07:06:12.191617Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4366068,
    events_root: None,
}
2023-02-17T07:06:12.193018Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-17T07:06:12.193138Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.079881ms
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