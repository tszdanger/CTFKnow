# CTFKnow: Measuring and Augmenting Large Language Models for Solving Capture-the-Flag Challenges

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Paper](https://img.shields.io/badge/Paper-PDF-red.svg)](paper.pdf)

## 📖 Overview

CTFKnow is a comprehensive research framework designed to measure and enhance Large Language Models (LLMs) capabilities in solving Capture-the-Flag (CTF) cybersecurity challenges. This project provides a complete pipeline for automated data collection, knowledge extraction, question generation, and model evaluation in the cybersecurity domain.

### 🎯 Key Features

- **Automated CTF Write-up Collection**: Scrapes high-quality write-ups from CTFtime.org
- **Intelligent Knowledge Extraction**: Uses LLMs to extract universal cybersecurity knowledge from write-ups
- **Automated Question Generation**: Creates both multiple-choice and open-ended questions
- **Comprehensive Model Evaluation**: Evaluates LLM performance on cybersecurity tasks
- **Vulnerable Code Dataset**: Builds datasets with vulnerable code snippets and exploitation scenarios
- **Multi-Model Support**: Compatible with various LLM providers (OpenAI, Replicate, etc.)

## 🏗️ Architecture

```
CTFKnow/
├── scraper/                 # Data collection module
│   ├── scraper.py          # Main scraper orchestration
│   ├── ctft/               # CTFtime.org specific scrapers
│   │   ├── get_writeup_url.py
│   │   ├── ctftime_scrape.py
│   │   └── souper.py
│   └── all.md              # Competition list
├── dataset/                # Data storage
│   ├── raw/                # Raw write-up files
│   ├── list.json           # Challenge metadata
│   ├── list_knwoledge_question.json
│   └── list_knwoledge_key.json
├── run.py                  # Main processing pipeline
├── prompts.py              # LLM prompt templates
└── paper.pdf              # Research paper
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key (or other LLM provider)
- Required Python packages (see installation section)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/tszdanger/CTFKnow.git
   cd CTFKnow
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up API keys**
   ```bash
   export OPENAI_API_KEY="your-openai-api-key"
   # For other providers, set appropriate environment variables
   ```

### Basic Usage

#### 1. Data Collection (Optional - Pre-collected data available)
```bash
cd scraper
python scraper.py
```

#### 2. Knowledge Extraction
```bash
python run.py K -i dataset/list.json -o dataset/knowledge.json
```

#### 3. Question Generation
```bash
python run.py Q -i dataset/knowledge.json -o dataset/questions.json -q dataset/question_list.json
```

#### 4. Model Evaluation
```bash
# Multiple choice evaluation
python run.py E -M single -l gpt-4-0125-preview -o evaluation_log.json

# Open-ended question evaluation
python run.py E -M open -l gpt-4-0125-preview -o evaluation_log.json
```

## 📊 Dataset Statistics

The CTFKnow dataset includes:

- **13,000+ CTF Challenges** from various competitions
- **6 Challenge Categories**: Web, Pwn, Reverse, Crypto, Forensics, Misc
- **2019-2024 Time Span**: Covers challenges from multiple years
- **Difficulty Distribution**: Normalized difficulty scores
- **Quality Filtered**: Only high-rated write-ups included

### Challenge Distribution

| Category | Count | Percentage |
|----------|-------|------------|
| Web | ~2,500 | 19% |
| Pwn | ~2,000 | 15% |
| Reverse | ~2,200 | 17% |
| Crypto | ~2,800 | 22% |
| Forensics | ~1,800 | 14% |
| Misc | ~1,700 | 13% |

## 🔧 Core Components

### 1. Data Collection Module (`scraper/`)

The scraper module automatically collects CTF write-ups from CTFtime.org:

- **Competition Discovery**: Automatically finds CTF competitions
- **Write-up Selection**: Chooses highest-rated write-ups for each challenge
- **Content Processing**: Converts HTML to clean Markdown format
- **Metadata Extraction**: Captures challenge type, difficulty, and competition info

```python
# Example: Scraping a specific competition
from scraper.ctft.get_writeup_url import list_writeups
writeups = await list_writeups("https://ctftime.org/event/1234/tasks/")
```

### 2. Knowledge Extraction (`Knowledge` class)

Extracts universal cybersecurity knowledge from write-ups:

- **LLM-Powered Extraction**: Uses GPT-3.5-turbo for knowledge identification
- **Universal Knowledge**: Focuses on transferable security concepts
- **Structured Output**: Generates standardized knowledge representations
- **Payload Examples**: Includes practical exploitation examples

```python
# Example: Knowledge extraction
from run import Knowledge
extractor = Knowledge('dataset/list.json', 'dataset/knowledge.json')
extractor.extract()
```

### 3. Question Generation (`Question` class)

Generates assessment questions from extracted knowledge:

- **Multiple Choice Questions**: Creates 4-option questions with distractors
- **Open-Ended Questions**: Generates short-answer questions
- **Difficulty Scaling**: Questions match original challenge difficulty
- **Quality Control**: Ensures question clarity and correctness

```python
# Example: Question generation
from run import Question
generator = Question('dataset/knowledge.json', 'dataset/questions.json', 'dataset/question_list.json')
generator.generate()
```

### 4. Model Evaluation (`Evaluation` class)

Comprehensive evaluation of LLM performance:

- **Multiple Metrics**: Accuracy, precision, recall, F1-score
- **Batch Processing**: Efficient evaluation of large question sets
- **Detailed Logging**: Comprehensive evaluation logs
- **Model Comparison**: Easy comparison between different LLMs

```python
# Example: Model evaluation
from run import Evaluation
evaluator = Evaluation('gpt-4-0125-preview', 'dataset/question_list.json')
results = evaluator.envaluate()
```

## 🎯 Use Cases

### 1. LLM Security Assessment
Evaluate how well different LLMs perform on cybersecurity tasks:

```bash
# Compare multiple models
python run.py E -M single -l gpt-4-0125-preview -o gpt4_results.json
python run.py E -M single -l claude-3-opus -o claude_results.json
python run.py E -M single -l llama-3-70b -o llama_results.json
```

### 2. Security Education
Generate educational content for cybersecurity training:

```bash
# Generate questions for specific categories
python run.py Q -i dataset/web_knowledge.json -o web_questions.json -q web_question_list.json
```

### 3. Research Benchmark
Use as a standardized benchmark for security AI research:

```bash
# Full pipeline for research
python run.py K -i dataset/list.json -o dataset/knowledge.json
python run.py Q -i dataset/knowledge.json -o dataset/questions.json -q dataset/question_list.json
python run.py E -M single -l your-model -o research_results.json
```

### 4. Vulnerability Analysis
Build datasets with vulnerable code for security research:

```bash
python run.py B -l dataset/list.json -o dataset/vulnerable_code.json
```

## 📈 Performance Metrics

CTFKnow provides comprehensive evaluation metrics:

- **Accuracy**: Overall correct answer rate
- **Category-wise Performance**: Performance breakdown by challenge type
- **Difficulty Analysis**: Performance across different difficulty levels
- **Question Type Analysis**: Multiple choice vs. open-ended performance
- **Confidence Analysis**: Model confidence vs. accuracy correlation

## 🔧 Advanced Configuration

### Custom Prompts
Modify `prompts.py` to customize LLM interactions:

```python
# Example: Custom knowledge extraction prompt
CUSTOM_EXTRACTION_PROMPT = """
You are an expert cybersecurity analyst. Extract the core security concepts from this CTF write-up.
Focus on universal principles that apply across different scenarios.
"""
```

### Model Integration
Add support for new LLM providers in `run.py`:

```python
# Example: Adding new model support
def query_custom_model(input, system_prompt):
    # Implement your model API call here
    response = your_model_api(input, system_prompt)
    return response, 1
```

### Data Processing Pipeline
Customize the data processing workflow:

```python
# Example: Custom data preprocessing
class CustomKnowledge(Knowledge):
    def preprocess_writeup(self, writeup_content):
        # Add your preprocessing logic
        return processed_content
```

## 📚 API Reference

### Main Classes

#### `Buildinit`
Initializes the dataset and generates statistics.

```python
init = Buildinit('dataset/list.json', 'dataset/raw', 'dataset/data.json')
init.build()  # Build initial dataset
init.draw_graph()  # Generate statistics
```

#### `Knowledge`
Extracts cybersecurity knowledge from write-ups.

```python
extractor = Knowledge('dataset/list.json', 'dataset/knowledge.json')
extractor.extract()  # Extract knowledge
extractor.save_data()  # Save results
```

#### `Question`
Generates questions from extracted knowledge.

```python
generator = Question('dataset/knowledge.json', 'dataset/questions.json', 'dataset/question_list.json')
generator.generate()  # Generate questions
generator.convert_questions()  # Convert to open-ended
```

#### `Evaluation`
Evaluates LLM performance on generated questions.

```python
evaluator = Evaluation('model-name', 'dataset/question_list.json')
evaluator.envaluate()  # Multiple choice evaluation
evaluator.envaluate_short_answer()  # Open-ended evaluation
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/tszdanger/CTFKnow.git
cd CTFKnow
pip install -r requirements-dev.txt
pre-commit install
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📖 Citation

If you use CTFKnow in your research, please cite our paper:

```bibtex
@article{ji2025measuring,
  title={Measuring and Augmenting Large Language Models for Solving Capture-the-Flag Challenges},
  author={Ji, Zimo and Wu, Daoyuan and Jiang, Wenyuan and Ma, Pingchuan and Li, Zongjie and Wang, Shuai},
  journal={arXiv preprint arXiv:2506.17644},
  year={2025}
}
```



---
