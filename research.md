# IDEA
binary code analysis is useful for many purposes, including reverse engineering and vulnerability research. However, LLMs mainly rely on external tools like disassemblers (Ghidra, IDAPro, Binary Ninja etc.) to get useful information. But there is another hurdle to address. While these RE tools have many feature, thye still have limitations when extracting non-trivial properties of the binary being analysed, like dataflow (inter- and intra-procedural). they provide scripting env where one can write script in their APIs, but there are still limitation. On the other hand, DSL like datalog have very powerful ways to represent the programs as logical formulas and then compute over them extablised the presence or absence of the properties. this happens via extracting facts and then answering questions bae on those facts.
I would like to explore a combination of LLM, disassembles (BN or Ghidra via MCP) and locally installed Souffle datalog compiler to answers queries about non-trivial properties of the binary. Specifically I am thinking:
1. LLM interacts with the use as via agents.
2. It has access to Ghidra/BN MCP tools to extract explicit facts about the binary.
4. Based on the use queries, either it can answer them directly via MCP tools OR it can generate a datalog file (in the proper datalog format) by populating facts using tools via MCP. This is a dynamic part.
3. Using python subprocess, it can run souffle compiler of that .dl file ad get the response.
4. continue in the loop, until user's query is not answered

How does it sound? I know it is still a bit vague and I like to have more clarity and a solid plan to start developing this project.

# References

1. MATE project: https://galoisinc.github.io/MATE/
2. https://github.com/galoisinc/cclyzerpp
3. https://github.com/GrammaTech/ddisasm