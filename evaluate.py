"""Evaluate authored supported-pattern examples; never emit fixture text."""
import json
from pathlib import Path
from redaction import redact

def evaluate():
    cases=json.loads((Path(__file__).parent/'fixtures'/'evaluation.json').read_text())
    tp=fp=fn=tn=0
    for case in cases:
        detected=set(redact(case['text'])['counts'])
        expected=set(case['expected'])
        if expected:
            if detected == expected: tp+=1
            else: fn+=1
        elif detected: fp+=1
        else: tn+=1
    return dict(cases=len(cases),true_positive=tp,false_negative=fn,false_positive=fp,true_negative=tn,
                note='Authored supported-format examples only; not a measure of real-world DLP coverage.')

if __name__=='__main__':print(json.dumps(evaluate(),indent=2))
