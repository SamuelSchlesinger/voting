# Deployment

There are several ways one could imagine deploying such a system. In each case,
the issuance mechanism is probably bespoke. One example of issuance is where
you have some pre-existing way of knowing that someone is within some group.

For example, a government could issue credentials to individuals based on their
identity documents. As another example, a company could issue credentials based
on their membership in the firm.

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

## Bespoke Approach

Another approach is to build a bespoke system to solve this problem. This is
much harder, and requires careful thought to avoid issues such as:

1. Censorship, as in the blockchain case
2. Voting after expiration, which is stopped in the blockchain approach by
   including transactions in a block where we also have a timestamp

I'll try to write up a design for this soon, but I want to make sure I get it
right, ideally with a proof of correctness.
