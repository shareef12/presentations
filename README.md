# Presentations

This repo contains public presentations given by myself, along with any
associated code samples.

## AvengerCon '17 - Windows 10 Arbitrary Code Guard

With the release of Windows 10 Creators Update, Microsoft introduced two new
exploit mitigations for processes: Code Integrity Guard (CIG) and Arbitrary
Code Guard (ACG). These mitigations greatly increase the difficulty of browser
exploitation and have significant implications for code injection. As of build
1703, CIG and ACG are enabled by default for Microsoft Edge and Hyper-V child
processes. In this talk, we'll examine these mitigations from an attacker's
perspective and discuss how code injection might be performed in this
restricted environment.

## Hammertime '19 - Introduction to Clang/LLVM

LLVM's modular architecture allows for easy compiler hacking and program
analysis. This talk will be a brief introduction to Clang/LLVM. We'll cover
some of the core data structures and techniques LLVM uses when compiling code,
and take a brief look at some of the intermediate representations before
writing a simple optimization pass to demonstrate how to interact with the LLVM
IR.
