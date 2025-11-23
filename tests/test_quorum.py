from textwrap import dedent

import pytest

from sigmon.sigsum import TreeHead, QuorumPolicy, QuorumUnsatisfiedError
from sigmon.utils import sha256

LOG_KEY_RAW = bytes.fromhex('0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25')
LOG_KEY_HASH = sha256(LOG_KEY_RAW)

TREE_HEAD = TreeHead.from_ascii(LOG_KEY_HASH, """
size=12851
root_hash=4ccedda0c3e6afc83cfcddfad7df3d95cbd1e857ecf3cf0569b8f69ce32727f8
signature=880207e73dbe7aa11ebab8118d4da67e59a2ff29d9b11e98b8d5d4062dbd4d12765b5389b4f0583130fa8573cf997d60b94c9e4d700469aba5a9f4383f619509
cosignature=768c9aac6ea5ee9b9c75dd862b70dcb693a2cb37c4ae2f15064e34a1ab260b01 1754020861 bb50b9e163bb1854c5634ebbdd32e3e23142390e08272f0773d187f51386cfdd81d1ad74ae708f55964edcd2d415f44eaaa4967418839ac13aba6db0e7ac750e
cosignature=3573fb7fdab7434cd0dad9fd6460abf420388055db8aaaec177c248f03a990cc 1754020861 aaddf982992263fbf18e5bd0c987dce77e4dcb6d1839a7120693fc027adbfe2874c4a17f86e9da66a74e2bde7936dc762b66ce07229ef3424ef330dbc586960c
cosignature=6d6a78191e59815eff9131941fc3e08dd716a281c8b886dd67880d552e587a23 1754020863 b4b53936c7f158cbd207dd673cc05980b4fec81fa9646135f4bb0de8b2149d502ab9447a393c8432ce7c3d690ecf615640d9e6b7a9ba30bbc7351599cabb4702
cosignature=b24254eb2c769e3c9f40b4268cd92b30cdb58c5a3c65e4f09f6475a6487e56d0 1754020862 f26139b4a9de9f09e1f874990428b92f236d185d80abb48a4140eb8349bab81fa93144d9d1a9e68f9a56429f9f46984ad0a6d3f6eddb0d601cb7d36fcb2a6105
cosignature=6bdf03b285fce48e00ff9b199cb2b77472dcc4a112f067fa5b274929cb9504e3 1754020861 9ab58c0f6cbfd02549891b3b9d7e68fd7fefd42b6dc22fbbee7ed3119d1ed1807edc74c8b12fd430e4ee6084b59077d4c8eafe09eefdbbe31666828c34d24702
cosignature=5da2b3803c2f802eed9744b74e3e4a3d31e1e77ed994ef56730d57fa52f698a5 1754020861 82f16ff572ba54e6f0b2f27e0e34fa729ab42d566b1d54a0b689d345c373fd0d87a61a6b6e81b4d17b3ca9f13f01a6c1325d701e6350ecddfa54b6b453691d0f
cosignature=0dad9d849c57687454f100d87fa729b54cb69f7af97346613348defcba9c361c 1754020861 442f4e9a466a60de8cc706ff6d01acd0150c86ec915128ab36375cd3ee013b13675e96c2c2e83abb1b8992824b05f9eefe4afe3f046e7b491897da7dc395570d
cosignature=9a0dcddbd96f6d6d404227b5ff23de7a43f25cdde9790af5ace332d347fac49a 1754020861 1a7cb189ca8bdac6743d1ed2d77fa7012509e6deebe2aee070221e860d51ab17c038ba493a27748922dc100299d8068dcb82397dd80efc679dfbf4b46b9b0a00
cosignature=d59098d686f47ec1d4d1984c8ac0ab97a3d8a65c7ba8cb6422ada0fae927e194 1754020861 0177a303e75ddaef7aeff9ed8a50218866b431328d4ea5d9cae7eaae9d935a3c03102b5df23e1d4e0303c773ea84d1978189c2d4e8adb3ad815f9169dcbced05
cosignature=0b00d26b3bf3e0ded29f82803abd34c972cb62752305b0e718cf7b8ec1bf99f6 1754020861 0e938f0d3935e9842855191a799336584afb47986848bc6312bdcd45606cbf2ac042b8a416db1381bf6f4b9e7a084de982b1ddb4704d53253deaf415f60e320a
cosignature=0de5858fa7d8770c17cd17decf4d6345120736308786885b3623bcb852324416 1754020861 9b01158eb701ca6cd814f603918ba32c59a1b3618cfbf94090e5d8c0ee978559570510867135a596c9cd9944cf4bf4f300206f613aaa9eab3f92f8a68fed6b0d
cosignature=81538d254f0a67aa07172826ef46fe0cd04b7425bd634a50bb0a8419d55fa65f 1754020861 02a7141b0dd172972a3a0f127218546d4a760479b995d02c4691022e60898bd14ec7f8c260dd6f3f1b2edab206c7806c3efe587ac0b1a9201889437bf4c1d10e
cosignature=cd02db1cc0488c28245d7c3ff50b3e214334c067f2571e849425146bb6bd173d 1754020861 ade49be9a8f1b5633cd7675f8f94ce00ec398a3fd5b96d77dfaa960b4ed78584d99379db73c54ef5ecf7bfeacc744345a0dcf5588ca4febf313af6ffe05c090e
cosignature=f7a8e45707ef65b294a899fd6a8f463b663e843f68c829bc00447171a582de24 1754020861 12fb3c6e7732a6e8f6fea8e8adf2e07826118914ad05be55b9803fdbf309ff479569bec38cea16367b7dce8f0f5899881f6c8bef0a1f49bb579f140eea9a3707
cosignature=f6f91669f7955f542718af9edb6a1276d88a0f8822cba9046e549d0b3796f394 1754020861 573c856a7e7cd3f1f764911c7ee70cc14677928405d7b82c531e882322eb38a94bc6aa738856613109f49c05d3af5ccc24b989be591fb19d7827a1bfa9e27d07
cosignature=506972ae99f752df639c749ac50a741b80d95f114a35420838ac06107ea9bfe8 1754020861 bcaaff25f70a04bc2d08d0c428e595d80cac19eb9f68dd65e95f5d0d2c16c3185252c4f30f7ae7dca861fee34a7661643d116a00bcf2c8fc97d8d3cbae34a70b
cosignature=ff2f237a707a2d3a6adfb1600d3375cafe4527ba4fcec793e6093b9b1a4bd79a 1754020861 308e724f50b9ada63a2bfd9b0143345aa1ea3a793d4db4de1e4842d9643d926b8a6711017482f5bebbfb0fefe4e3f620151b5ef020ad30569595094563465000
""")

def test_none_quorum():
    quorum = QuorumPolicy.from_policy("quorum none")
    quorum.check(TREE_HEAD)

def test_witness_quorum():
    quorum = QuorumPolicy.from_policy(dedent("""
    witness witness.glasklar.is b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536
    quorum witness.glasklar.is
    """))
    quorum.check(TREE_HEAD)

def test_group_quorum():
    for size in range(1, 4):
        quorum = QuorumPolicy.from_policy(dedent(f"""
        witness witness.glasklar.is b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536
        witness witness.mullvad.net 15d6d0141543247b74bab3c1076372d9c894f619c376d64b29aa312cc00f61ad
        witness dummy               c919c09e4532b565f27b3b9eb6d794bd3ea72162157613ac05493294a5847656
        group group {size} witness.glasklar.is witness.mullvad.net dummy
        quorum group
        """))

        if size < 3:
            quorum.check(TREE_HEAD)
        else:
            with pytest.raises(QuorumUnsatisfiedError):
                quorum.check(TREE_HEAD)

def test_invalid_quorum_rule():
    policies = [
        # witness name collision
        ('already exists', """
        witness dummy              0000000000000000000000000000000000000000000000000000000000000000
        witness dummy              0000000000000000000000000000000000000000000000000000000000000000
        quorum dummy
        """),

        # group name collision
        ('already exists', """
        witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
        witness dummy2             0000000000000000000000000000000000000000000000000000000000000000

        group foo any dummy1
        group foo any dummy2
        quorum dummy1
        """),

        # witness/group name collision
        ('already exists', """
        witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
        group dummy1 any dummy1
        quorum dummy1
        """),

        # unknown group member
        ('unknown entity', """
        witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
        group group any dummy2
        quorum dummy1
        """),

        # empty group
        ('no member', """
        group group any
        quorum group
        """),

        # zero threshold
        ('invalid threshold', """
        witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
        group group 0 dummy1
        quorum dummy1
        """),

        # excessive threshold
        ('invalid threshold', """
        witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
        group group 2 dummy1
        quorum dummy1
        """),

        # multiple quorum lines
        ('multiple quorum', """
        witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
        quorum dummy1

        witness dummy2             0000000000000000000000000000000000000000000000000000000000000000
        quorum dummy2
        """),

        # entity called "none"
        ('"none" is reserved', """
        witness none               0000000000000000000000000000000000000000000000000000000000000000
        quorum none
        """),

        # quorum missing
        ('quorum not specified', """
        witness dummy              0000000000000000000000000000000000000000000000000000000000000000
        """),
    ]

    for match, pol in policies:
        with pytest.raises(ValueError, match=match):
            QuorumPolicy.from_policy(dedent(pol))

def test_invalid_cosignature():
    th = TreeHead.from_ascii(LOG_KEY_HASH, dedent("""
    size=12851
    root_hash=4ccedda0c3e6afc83cfcddfad7df3d95cbd1e857ecf3cf0569b8f69ce32727f8
    signature=880207e73dbe7aa11ebab8118d4da67e59a2ff29d9b11e98b8d5d4062dbd4d12765b5389b4f0583130fa8573cf997d60b94c9e4d700469aba5a9f4383f619509
    cosignature=6bdf03b285fce48e00ff9b199cb2b77472dcc4a112f067fa5b274929cb9504e3 1234567890 9ab58c0f6cbfd02549891b3b9d7e68fd7fefd42b6dc22fbbee7ed3119d1ed1807edc74c8b12fd430e4ee6084b59077d4c8eafe09eefdbbe31666828c34d24702
    """))

    policy = QuorumPolicy.from_policy(dedent("""
    witness witness.glasklar.is b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536
    quorum witness.glasklar.is
    """))

    # we currently deliberately don't raise a crypto error here but rather just
    # ignore the witness, which should cause the quorum to fail
    with pytest.raises(QuorumUnsatisfiedError):
        policy.check(th)

