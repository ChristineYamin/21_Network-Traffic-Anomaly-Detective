## Project 21

### The meaining of the columns
dur - How long the connection lasted, in seconds

proto - The communication method, or protocol

spkts - Number of data packets sent by the source computer

dpkts - Numbers of packets sent back by the destination computer

attack_cat - The type assigned by the dataset researchers

label - 0 = normal, 1 = attack 


## NB1 :
Can We spot attacks by looking at information about computer connections?
1. We looked at the dataset. Each row is one connection; label tells us whether it was normal (0) or an attack (1).
2. We tried a simple rule: flag connections with no reply. It caught some attacks but missed many.
3. We tried two models. Random Forest caught far more attacks than Isolation Forest.
4. We checked its mistakes. On the official test set, our selected Random Forest caught about 99% of attacks, but also flagged 11,544 normal connections.
5. We investigated those false alarms and found many involved normal FIN connections. Removing one heavily used clue did not fix the problem.
In one sentence: we built an attack detector, measured how well it worked, and found that its many false alarms are the main problem to explain in our project.
( iT CATCHES ATTACKS BUT ALSO MANY False alarms)

