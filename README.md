# CTFKnow
Repo for paper *Measuring and Augmenting Large Language Models for Solving Capture-the-Flag Challenges*

## CTFAgent: Benchmark

raw write-up in dataset/raw

### Evaluation

(single choice question)
```bash
python run.py -E -M single -l gpt-4-0125-preview -o log.json
```

or 

(open-ended question)
```bash
python run.py -E -M open -l gpt-4-0125-preview -o log.json
```

### Bechmark Building

Run with -K and -Q.

If you need vulnerable code snippet with key, run with -B.