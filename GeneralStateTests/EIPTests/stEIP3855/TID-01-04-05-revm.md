> Executed Command

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
2023-02-26T14:20:17.685621Z  INFO revme::statetest::cmd: Start running tests on: "tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-26T14:20:17.685873Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686028Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686105Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686134Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686160Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686191Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686217Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686252Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.686289Z  WARN revme::statetest::runner: Processing 1/1
2023-02-26T14:20:17.689203Z DEBUG revme::statetest::runner: Pre Processing => "push0"
2023-02-26T14:20:17.689313Z  INFO revme::statetest::runner: Pre Acc :: 0x00000700
2023-02-26T14:20:17.689323Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.689385Z  INFO revme::statetest::runner: Pre Acc :: 0x00000100
2023-02-26T14:20:17.689392Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.689442Z  INFO revme::statetest::runner: Pre Acc :: 0xb94fbf0b
2023-02-26T14:20:17.689449Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.689664Z  INFO revme::statetest::runner: Pre Acc :: 0x00000300
2023-02-26T14:20:17.689671Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.689700Z  INFO revme::statetest::runner: Pre Acc :: 0xa94fbf0b
2023-02-26T14:20:17.689706Z  INFO revme::statetest::runner: balance :: 17592186044416
2023-02-26T14:20:17.690111Z  INFO revme::statetest::runner: Pre Acc :: 0x00000200
2023-02-26T14:20:17.690117Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.690170Z  INFO revme::statetest::runner: Pre Acc :: 0x00000500
2023-02-26T14:20:17.690176Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.690237Z  INFO revme::statetest::runner: Pre Acc :: 0x00000400
2023-02-26T14:20:17.690243Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.690295Z  INFO revme::statetest::runner: Pre Acc :: 0x00000600
2023-02-26T14:20:17.690301Z  INFO revme::statetest::runner: balance :: 0
2023-02-26T14:20:17.690316Z DEBUG revme::statetest::runner: Executing Spec => Merge
2023-02-26T14:20:17.690530Z  INFO revme::statetest::runner: exit_reason::[Stop], gas_used::[148031], gas_refunded::[0], logs::[[]]
2023-02-26T14:20:17.690551Z  INFO revme::statetest::merkle_trie: State info for => "b94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-26T14:20:17.690564Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.690572Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.690584Z  INFO revme::statetest::merkle_trie: (
    0x0000000000000000000000000000000000000000000000000000000000000001,
    b"\x01",
)
2023-02-26T14:20:17.690679Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: af75e120bc9b2b813d81494fcb57703dcd277a3dab4cefbfb6e8188c8c101d6b
2023-02-26T14:20:17.690692Z  INFO revme::statetest::merkle_trie: State info for => "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
2023-02-26T14:20:17.690699Z  INFO revme::statetest::merkle_trie: nonce :: 1
2023-02-26T14:20:17.690706Z  INFO revme::statetest::merkle_trie: balance :: 17592184564106
2023-02-26T14:20:17.690746Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
2023-02-26T14:20:17.690756Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000100"
2023-02-26T14:20:17.690762Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.690769Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.690807Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: 0125401e1ab3861d0d9dd8099943b70a1fd558be51c551394387321c48cf5d97
2023-02-26T14:20:17.690816Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000200"
2023-02-26T14:20:17.690823Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.690829Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.690869Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: a44ddbe3846599b1b2ca0594fb0cb0c2d6d63b877ce5ddb234339190f6535058
2023-02-26T14:20:17.690879Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000500"
2023-02-26T14:20:17.690885Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.690892Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.690930Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: edcea87ee48aa9a04c103b5b3c70ed9ff9fe2588bd460852de66d194439bd683
2023-02-26T14:20:17.690940Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000700"
2023-02-26T14:20:17.690947Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.690953Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.690991Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: 29c955fec03398c668c9f67fcd2c1d24e301c426a12737ce10c33113443a8410
2023-02-26T14:20:17.691002Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000600"
2023-02-26T14:20:17.691009Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.691016Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.691056Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: fd9bdc48c415ec6f74ded272c8758e673376fc007812223384f6eea1588dab60
2023-02-26T14:20:17.691065Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000300"
2023-02-26T14:20:17.691072Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.691078Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.691116Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: cc61b581b699b895ad2557e2aa9578bcf05d163d6c03a900a38e312bdfc2f79b
2023-02-26T14:20:17.691127Z  INFO revme::statetest::merkle_trie: State info for => "0000000000000000000000000000000000000400"
2023-02-26T14:20:17.691133Z  INFO revme::statetest::merkle_trie: nonce :: 0
2023-02-26T14:20:17.691140Z  INFO revme::statetest::merkle_trie: balance :: 0
2023-02-26T14:20:17.691148Z  INFO revme::statetest::merkle_trie: (
    0x0000000000000000000000000000000000000000000000000000000000000001,
    b"\n",
)
2023-02-26T14:20:17.691186Z  INFO revme::statetest::merkle_trie: (
    0x0000000000000000000000000000000000000000000000000000000000000000,
    b"\n",
)
2023-02-26T14:20:17.691322Z  INFO revme::statetest::merkle_trie: bytecode_hash.0 :: 48191a2b9cc0ce9f46786b06bc6b47348b83d5e37b8bde367268384d07df718b
2023-02-26T14:20:17.691903Z  INFO revme::statetest::runner: Post Hash Check ::
2023-02-26T14:20:17.691912Z  INFO revme::statetest::runner: Calc :: 0x84893d9a4161a9cf913c9c53a1827b7a3abfa2f0b57216e605b7cb87f527ae72
2023-02-26T14:20:17.691922Z  INFO revme::statetest::runner: Actual :: 0x84893d9a4161a9cf913c9c53a1827b7a3abfa2f0b57216e605b7cb87f527ae72
2023-02-26T14:20:17.691949Z DEBUG revme::statetest::runner: TestDone => 0/"tests/GeneralStateTests/EIPTests/stEIP3855/mod-push0.json"
2023-02-26T14:20:17.692014Z  WARN revme::statetest::runner: Processing 1/1
Finished execution. Time:201.096s
```
