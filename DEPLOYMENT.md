# Deployment

There are several ways one could imagine deploying such a system. In each case,
the issuance mechanism is probably bespoke. One example of issuance is where
you have some pre-existing way of knowing that someone is within some group.

For example, a government could issue credentials to individuals based on their
identity documents. As another example, a company could issue credentials based
on their membership in the firm.

## Just Some Server

For some friends who want to deploy anonymous voting for their use cases, just
some random server is a totally reasonable way to deploy this system. In
particular, just have someone you trust set up a server which collects and
verifies votes. If users feel extra paranoid about the server actually
capturing and recording who voted for what via fingerprinting of some sort,
then they can connect to the server via a VPN.

If you want to get fancy, OHTTP might be a useful thing. I need to learn more
about this.

## Trusted Execution Environment

This is a great use case for a Trusted Execution Environment. In particular,
we can deploy a single vote collector in a Trusted Execution Environment that
only permits votes to be cast up to a certain time, and after that time allows
arbitrary clients to query the vote set.

However, it is important to note that such a system has another root of trust,
the hardware provider. In a use case such as governmental elections, this root
of trust might not be appropriate.

## Blockchain

This is probably the most straightforward deployment option. Essentially, you
deploy a smart contract which accepts and verifies votes. At a certain time,
the contract stops accepting votes and then everyone can observe which
candidate got the most votes by just counting from the list on chain. Further,
the smart contract can have some convenience functions for calculating who won
for you, and you can trust this if you trust the smart contract.

### Censorship Issues

Nodes can censor users who are voting in ways they don't prefer. In practice,
unless a network is highly centralized, this is likely not a problem for
practical deployments. For use cases which have broad impact, like government
elections, this should strongly be taken into account. However, for a small
group holding anonymous elections on some mostly irrelevant thing to the nodes,
it seems like this is a perfectly appropriate deployment pattern.

## Decentralized Approach

Another approach is to build a bespoke system to solve this problem. This is
much harder, and requires careful thought to avoid issues such as:

1. Censorship, as in the blockchain case
2. Voting after expiration, which is stopped in the blockchain approach by
   including transactions in a block where we also have a timestamp

I'll try to write up a design for this soon, but I want to make sure I get it
right, ideally with a proof of correctness.
