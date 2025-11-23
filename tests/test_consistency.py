from textwrap import dedent

from sigmon.sigsum import ConsistencyProof

def test_rgdd():
    "https://gitlab.torproject.org/rgdd/ct consistency test vectors"

    def verify_consistency(old_size, new_size, old_root, new_root, proof):
        cp = ConsistencyProof(
            proof,
            old_size,
            new_size
        )

        return cp.check(old_root, new_root)

    TreeHeadEmpty = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    TH0T0         = bytes.fromhex('db3426e878068d28d269b6c87172322ce5372b65756d0789001d34835f601c03')
    TH0T1         = bytes.fromhex('cb00989d94a569c0a678ae042b63dcd4625db96440517f37a6eb7976ea24ed4b')
    TH0T2         = bytes.fromhex('725d5230db68f557470dc35f1d8865813acd7ebb07ad152774141decbae71327')
    TH0T3         = bytes.fromhex('9f4a3fc20d4162dc37d4e23d907848731a76043ffff6d69288bf1abfbcff478e')
    TH0T4         = bytes.fromhex('b6748f6ed7a99de7da84fd97e1a3bac6fab8999f4a43695cab9528a2de431147')
    TH0T5         = bytes.fromhex('32805cc5e94134743d0aa580ef2ee332687b687fc2e4e2f72fee1cc712e0ba0c')
    TH0T6         = bytes.fromhex('a3e23b32ccb6bf96d092d165d8aa546e09829de8f03b0e8957581d1e16b92bdf')
    TH0T7         = bytes.fromhex('3b85a9626c1ccb64c6b95ec7fa64888defe2cf12e39e77e10812ce5fcb9cb58e')
    TH0T8         = bytes.fromhex('e10cb99e8a9c48ae8a25e6c37ab3c88e6c93e8cf2a62cf7e4dcac1ea597e77d4')
    TH0T9         = bytes.fromhex('2f03f203d1fa3a6e1388fa4cb5187c3b4f94762e578e0106815140e6a8c6bd21')
    TH1T1         = bytes.fromhex('2215e8ac4e2b871c2a48189e79738c956c081e23ac2f2415bf77da199dfd920c')
    TH2T2         = bytes.fromhex('fa61e3dec3439589f4784c893bf321d0084f04c572c7af2b68e3f3360a35b486')
    TH2T3         = bytes.fromhex('d51f2dfecb59566dabdbb6b40bf651cdf39e677b4425165e217590ff3e010edb')
    TH3T3         = bytes.fromhex('906c5d2485cae722073a430f4d04fe1767507592cef226629aeadb85a2ec909d')
    TH4T4         = bytes.fromhex('11e1f558223f4c71b6be1cecfd1f0de87146d2594877c27b29ec519f9040213c')
    TH4T5         = bytes.fromhex('d2737dce8a7df1d7d5cf4d5f52d274802c71bfe20a2e078682e71c182d398c90')
    TH4T6         = bytes.fromhex('973f083957c7359fb1943acf9e6689bca6ca5ea7197d808aad3c14498689efe0')
    TH4T7         = bytes.fromhex('31f2973ab63e19375dfe0d165a92ebd9a13d28b5e6fc78072c4068bd7bbfbc37')
    TH5T5         = bytes.fromhex('53304f5e3fd4bcd20b39abdef2fe118031cc5ae8217bcea008dea7e27869348a')
    TH6T6         = bytes.fromhex('3bf9c81c231cae70b678d3f3038f9f4f6d6b9d7adcf9b378f25919ae53d17686')
    TH6T7         = bytes.fromhex('f384a00ff1483ad123c05cb5035c9bfa46a2d925548a5fa36acf1776c9b0f448')
    TH7T7         = bytes.fromhex('797427cf8368051fe7b8e3e9d5ade9c5bc9d0cf96f4f3fad2a1e1d7848368188')
    TH8T8         = bytes.fromhex('195f58bc6d6b7b36335c95e08343825a7ae6f30437b4a7e6fa7b89d76907570a')
    TH8T9         = bytes.fromhex('083f26cb62e982bf2dee404ad94736c02b0fe4ec2fc3d3281f4c0f410d740462')
    TH9T9         = bytes.fromhex('85224a5c0186b205a3e0a1ac0ac023bfb8cc6f4bf19c90be88fc5f0c2316a9fa')

    cases = [
        # Size 0
        (0, 0, TreeHeadEmpty, TreeHeadEmpty, []),

        # Size 1
        (0, 1, TreeHeadEmpty, TH0T0, []),
        (1, 1, TH0T0, TH0T0, []),

        # Size 2
        (0, 2, TreeHeadEmpty, TH0T1, []),
        (1, 2, TH0T0, TH0T1, [TH1T1]),
        (2, 2, TH0T1, TH0T1, []),

        # Size 3
        (0, 3, TreeHeadEmpty, TH0T2, []),
        (1, 3, TH0T0, TH0T2, [TH1T1, TH2T2]),
        (2, 3, TH0T1, TH0T2, [TH2T2]),
        (3, 3, TH0T2, TH0T2, []),

        # Size 4
        (0, 4, TreeHeadEmpty, TH0T3, []),
        (1, 4, TH0T0, TH0T3, [TH1T1, TH2T3]),
        (2, 4, TH0T1, TH0T3, [TH2T3]),
        (3, 4, TH0T2, TH0T3, [TH2T2, TH3T3, TH0T1]),
        (4, 4, TH0T3, TH0T3, []),

        # Size 5
        (0, 5, TreeHeadEmpty, TH0T4, []),
        (1, 5, TH0T0, TH0T4, [TH1T1, TH2T3, TH4T4]),
        (2, 5, TH0T1, TH0T4, [TH2T3, TH4T4]),
        (3, 5, TH0T2, TH0T4, [TH2T2, TH3T3, TH0T1, TH4T4]),
        (4, 5, TH0T3, TH0T4, [TH4T4]),
        (5, 5, TH0T4, TH0T4, []),

        # Size 6
        (0, 6, TreeHeadEmpty, TH0T5, []),
        (1, 6, TH0T0, TH0T5, [TH1T1, TH2T3, TH4T5]),
        (2, 6, TH0T1, TH0T5, [TH2T3, TH4T5]),
        (3, 6, TH0T2, TH0T5, [TH2T2, TH3T3, TH0T1, TH4T5]),
        (4, 6, TH0T3, TH0T5, [TH4T5]),
        (5, 6, TH0T4, TH0T5, [TH4T4, TH5T5, TH0T3]),
        (6, 6, TH0T5, TH0T5, []),

        # Size 7
        (0, 7, TreeHeadEmpty, TH0T6, []),
        (1, 7, TH0T0, TH0T6, [TH1T1, TH2T3, TH4T6]),
        (2, 7, TH0T1, TH0T6, [TH2T3, TH4T6]),
        (3, 7, TH0T2, TH0T6, [TH2T2, TH3T3, TH0T1, TH4T6]),
        (4, 7, TH0T3, TH0T6, [TH4T6]),
        (5, 7, TH0T4, TH0T6, [TH4T4, TH5T5, TH6T6, TH0T3]),
        (6, 7, TH0T5, TH0T6, [TH4T5, TH6T6, TH0T3]),
        (7, 7, TH0T6, TH0T6, []),

        # Size 8
        (0, 8, TreeHeadEmpty, TH0T7, []),
        (1, 8, TH0T0, TH0T7, [TH1T1, TH2T3, TH4T7]),
        (2, 8, TH0T1, TH0T7, [TH2T3, TH4T7]),
        (3, 8, TH0T2, TH0T7, [TH2T2, TH3T3, TH0T1, TH4T7]),
        (4, 8, TH0T3, TH0T7, [TH4T7]),
        (5, 8, TH0T4, TH0T7, [TH4T4, TH5T5, TH6T7, TH0T3]),
        (6, 8, TH0T5, TH0T7, [TH4T5, TH6T7, TH0T3]),
        (7, 8, TH0T6, TH0T7, [TH6T6, TH7T7, TH4T5, TH0T3]),
        (8, 8, TH0T7, TH0T7, []),

        # Size 9
        (0, 9, TreeHeadEmpty, TH0T8, []),
        (1, 9, TH0T0, TH0T8, [TH1T1, TH2T3, TH4T7, TH8T8]),
        (2, 9, TH0T1, TH0T8, [TH2T3, TH4T7, TH8T8]),
        (3, 9, TH0T2, TH0T8, [TH2T2, TH3T3, TH0T1, TH4T7, TH8T8]),
        (4, 9, TH0T3, TH0T8, [TH4T7, TH8T8]),
        (5, 9, TH0T4, TH0T8, [TH4T4, TH5T5, TH6T7, TH0T3, TH8T8]),
        (6, 9, TH0T5, TH0T8, [TH4T5, TH6T7, TH0T3, TH8T8]),
        (7, 9, TH0T6, TH0T8, [TH6T6, TH7T7, TH4T5, TH0T3, TH8T8]),
        (8, 9, TH0T7, TH0T8, [TH8T8]),
        (9, 9, TH0T8, TH0T8, []),

        # Size 10
        (0, 10, TreeHeadEmpty, TH0T9, []),
        (1, 10, TH0T0, TH0T9, [TH1T1, TH2T3, TH4T7, TH8T9]),
        (2, 10, TH0T1, TH0T9, [TH2T3, TH4T7, TH8T9]),
        (3, 10, TH0T2, TH0T9, [TH2T2, TH3T3, TH0T1, TH4T7, TH8T9]),
        (4, 10, TH0T3, TH0T9, [TH4T7, TH8T9]),
        (5, 10, TH0T4, TH0T9, [TH4T4, TH5T5, TH6T7, TH0T3, TH8T9]),
        (6, 10, TH0T5, TH0T9, [TH4T5, TH6T7, TH0T3, TH8T9]),
        (7, 10, TH0T6, TH0T9, [TH6T6, TH7T7, TH4T5, TH0T3, TH8T9]),
        (8, 10, TH0T7, TH0T9, [TH8T9]),
        (9, 10, TH0T8, TH0T9, [TH8T8, TH9T9, TH0T7]),
        (10, 10, TH0T9, TH0T9, []),
    ]

    for case, (old_size, new_size, old_root, new_root, proof) in enumerate(cases):
        # success case
        assert verify_consistency(old_size, new_size, old_root, new_root, proof), f"test case params[{case}] failed"

        # Changing the size of the old tree is similiar to changing the
        # index in an inclusion proof.  (One way to view a consistency
        # proof is as an inclusion proof to a particular subtree.)  So,
        # we know all 0 < i < new_size for i != old_size are invalid.
        for old_size2 in range(1, new_size):
            if old_size == old_size2:
                continue

            assert not verify_consistency(old_size2, new_size, old_root, new_root, proof), f"params[{case}] old size: {old_size2}"

        # Changing the size of the new tree is similar to changing the
        # size of the tree when proving inclusion.  We intentionally
        # test with a tree level that is off by one, for the same
        # reason as outlined above in the inclusion proof test.  Just
        # skip cases where the new tree is consistent per definition.
        for new_size2 in [new_size // 2, new_size * 2, new_size * 2 + 0x4634d422]:
            if old_size == 0:
                continue

            assert not verify_consistency(old_size, new_size2, old_root, new_root, proof), f"params[{case}] new size: {new_size2}"

        # Changing tree heads is always invalid, except when the old
        # tree is empty and the new tree isn't.  We will get a root
        # mismatch.
        hash_ = b'\x01' * 32
        assert not verify_consistency(old_size, new_size, hash_, new_root, proof), f"params[{case}] old tree head"

        if old_size:
            assert not verify_consistency(old_size, new_size, old_root, hash_, proof), f"params[{case}] new tree head"

        # It is always invalid to add or remove proof hashes; it puts
        # the tree size off by the number of added/removed hashes.  It
        # is always invalid to tamper with a single bit somewhere in
        # the proof: it creates a different tree head.

        proofs = []
        for i in range(0, len(proof)):
            p = proof.copy()
            p[i] = bytes([p[i][0] ^ 1]) + p[i][1:]
            proofs.append(p)
            proofs.append(proof[i+1:])

        for inner, proof2 in enumerate(proofs):
            assert not verify_consistency(old_size, new_size, old_root, new_root, proof2), f"params[{case}] inner {inner}"

def test_parse_ascii():
    proof = dedent("""
    node_hash=afad6ae234a601d44861f59da736e67b2a55c00a93b77b346f00721b57f18df7
    node_hash=e3e006db2ec949ed6fa18de8487d347ee6293dd22326649e46cdab3ba673e25f
    node_hash=21fbcfceada959fc837ec8eb0de186801baa9b8cfd5431469fe25d4e8d74b5b0
    node_hash=9739d644cd2a42be41866419fcfe65056efe6a2afdaeb616314217fc7f4d1006
    node_hash=b1ef9fed4f1b8e86c5d13e61c7d6bb259a8958139b1ad59086dba6dd46aafb7a
    node_hash=72545f8c68cd4e33e0ab8012be2a9054fba08fb8dd379e20d79b18207db9cc30
    node_hash=6ed6bab8c0d1440aa99f3ee8101aeb380ed7de12946335cf9dc6d96d93bc92c8
    node_hash=26807016f4669efb5600d29c45a141d8227a7e8dc3c206e82131aec08c14259e
    """)

    cp = ConsistencyProof.from_ascii(12849, 12851, proof)
    assert cp.check(
        bytes.fromhex("6ea77db6c6dbf3e5a026ba10d5ccf8ee68d2f385cc592e4e6c75f1c2b7f62969"),
        bytes.fromhex("4ccedda0c3e6afc83cfcddfad7df3d95cbd1e857ecf3cf0569b8f69ce32727f8")
    )
