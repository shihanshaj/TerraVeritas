"""Scanner adapters that collect evidence.

Scanners never decide whether a repair is correct — they only produce
normalized Finding objects. The oracle (terraveritas.verification) is the
only component allowed to classify a repair.
"""
